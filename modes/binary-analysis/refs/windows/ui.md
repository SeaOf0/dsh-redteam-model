# Windows UI 消息流逆向（自绘 UI · WndProc）

## 识别特征

```
- RegisterClassEx 使用自定义 WndProc（最终处理不是 DefWindowProc）
- WM_PAINT 手绘全部控件；没有标准 CreateWindowEx 子控件
- WM_NCPAINT/WM_NCCALCSIZE -> 自定义非客户区渲染
- WM_LBUTTONDOWN 通过手动命中测试而非标准按钮 HWND
- 重度使用 BitBlt/StretchBlt/AlphaBlend 做皮肤；资源位图作为按钮状态
```

## 消息分发流程

```
Step 1: IDA -> GetMessageW/PeekMessageW -> DispatchMessageW -> 主 WndProc

Step 2: 绘制 WndProc 的 switch/if 分支。关键消息：
  WM_PAINT (0x000F)       -> 绘制、皮肤渲染
  WM_LBUTTONDOWN (0x0201) -> 点击、手动 hit-test（关键）
  WM_KEYDOWN (0x0100)     -> 键盘快捷键
  WM_COMMAND (0x0111)     -> 菜单/加速键分发
  WM_USER+N (>=0x0400)    -> 内部消息协议（高价值）
  WM_APP+N  (>=0x8000)    -> 跨窗口消息

Step 3: x64dbg 在 WndProc 入口下条件断点： [esp+8]==0x0400+N -> 记录 wParam/lParam

Step 4: 定位控件状态结构（enabled/hovered/pressed/bounds RECT）
  WM_MOUSEMOVE -> 状态更新 -> WM_PAINT 重绘

Step 5: 映射点击 -> handler：
  WM_LBUTTONDOWN -> hit_test(x,y) -> element_index -> dispatch_action(element_index)
    case 0: feature_A(); case 2: validate_license()  -> 关键目标
  在 dispatch_action 的 RVA 处下 hook

Step 6: SetWindowsHookEx(WH_CALLWNDPROC)? -> 找到 lpfn -> 全局 hook
```

## UIElement 结构体（IDA 模板）

```c
struct UIElement {
    RECT    bounds;       // +0x00  hit-test rect
    int     state;        // +0x10  0=normal 1=hover 2=pressed 3=disabled
    int     id;           // +0x14  maps to WM_COMMAND/WM_USER dispatch
    HBITMAP hBmpNormal;   // +0x18
    HBITMAP hBmpHover;    // +0x20
    HBITMAP hBmpPressed;  // +0x28
    WCHAR   tooltip[128]; // +0x30
    LPVOID  onClick;      // +0xB0  handler function pointer
};
// IDA: xref hBmpNormal loads -> trace to global UIElement array
```
