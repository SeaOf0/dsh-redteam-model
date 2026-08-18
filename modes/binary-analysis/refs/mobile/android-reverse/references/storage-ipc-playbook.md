# Storage IPC Playbook

目标：补齐本地数据面与组件间通信面的取证。

## 关注对象

- `SharedPreferences`
- `SQLiteOpenHelper` / `Room`
- `MMKV`
- 文件缓存
- `ContentProvider`
- `Intent` / `Broadcast`
- `Binder` / AIDL 痕迹

## 必须回答

- 关键数据存在哪里
- 是否存在明文 token / key / 配置
- 组件间通过什么字段传递敏感数据
- Provider 或 IPC 是否成为关键入口

## 作业顺序

### 1. 识别存储机制

从静态分析入手，优先搜索以下特征：

- **imports**: `SharedPreferences`, `SQLiteDatabase`, `SQLiteOpenHelper`, `RoomDatabase`, `MMKV`, `ContentValues`, `openFileOutput`
- **文件模式**: `*.xml`(SP), `*.db`/`*.sqlite`(SQLite), `*.crc`/`MMKV` 目录, `files/`/`cache/`/`databases/`
- **第三方**: `mmkv`, `realm`, `objectbox`, `leveldb` 的 aar/so 特征

在 JADX 中全局搜索 `getSharedPreferences`、`openOrCreateDatabase`、`MMKV.defaultMMKV`、`Room.databaseBuilder`。

### 2. 定位敏感数据落盘点

追踪以下值的写入路径：

- token / session / refresh_token
- API key / secret / 加盐盐值
- 用户凭证（密码哈希、PIN）
- 设备指纹缓存、风控字段

重点关注 `apply()` / `commit()` 调用点、`insert()` / `update()` 调用点、以及 `openFileOutput` 写入时机。

### 3. 确认静态加密状态

对每个存储点判定：

- 明文存储 → 直接取证
- EncryptedSharedPreferences (AndroidX Security) → 检查 master key 来源
- 自定义加密 → 追踪加解密函数，确认 key 是否硬编码
- Android Keystore 绑定 → 追踪 `KeyStore.getInstance`、`KeyGenerator`，确认 key 是否可导出

### 4. 追踪 IPC 攻击面

- 搜索 `exported="true"` 的 ContentProvider 和 BroadcastReceiver
- 检查 `<grant-uri-permission>` 和 `path-permission` 配置
- AIDL 接口搜索 `*.aidl` 文件和 `Stub` 子类
- Intent 搜索 `putExtra` 中传递的敏感 key 名

### 5. 评估数据暴露风险

- 存储文件权限是否 `MODE_PRIVATE`（默认安全）还是 `MODE_WORLD_READABLE`（已废弃但仍可能存在）
- ContentProvider 是否做了调用方签名校验
- BroadcastReceiver 是否对来源做了验证
- Scoped Storage (Android 11+) 限制下，外部存储访问路径是否已迁移

## Frida Hook 锚点

### SharedPreferences 读写

```javascript
Java.perform(function () {
  var SP = Java.use("android.app.SharedPreferencesImpl");
  SP.getString.overload("java.lang.String", "java.lang.String").implementation = function (k, d) {
    var v = this.getString(k, d);
    console.log("[SP+GET] " + k + " = " + v);
    return v;
  };
  var Editor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
  Editor.putString.overload("java.lang.String", "java.lang.String").implementation = function (k, v) {
    console.log("[SP+PUT] " + k + " = " + v);
    return this.putString(k, v);
  };
});
```

### SQLiteDatabase 查询捕获

```javascript
Java.perform(function () {
  var DB = Java.use("android.database.sqlite.SQLiteDatabase");
  DB.execSQL.overload("java.lang.String").implementation = function (sql) {
    console.log("[DB+SQL] " + sql);
    this.execSQL(sql);
  };
  DB.insert.implementation = function (table, nullCol, values) {
    console.log("[DB+INS] table=" + table + " " + values);
    return this.insert(table, nullCol, values);
  };
});
```

### MMKV 读取

```javascript
Java.perform(function () {
  var MMKV = Java.use("com.tencent.mmkv.MMKV");
  MMKV.decodeString.overload("java.lang.String", "java.lang.String").implementation = function (k, d) {
    var v = this.decodeString(k, d);
    console.log("[MMKV+GET] " + k + " = " + v);
    return v;
  };
});
```

## 分析模式

### Room 数据库 Schema 提取

Room 编译期生成 `MyAppDatabase_Impl`，其中包含 `createAllTables` 方法，直接读取可获得完整建表语句。搜索 `@Database` 注解类和对应 `_Impl` 类。

### ContentProvider SQL 注入测试

对 exported ContentProvider：

1. 用 `adb shell content query --uri content://<authority>/<path>` 做基础探测
2. 尝试注入 `' OR '1'='1` 到 selection 参数
3. 检查 `query()` / `call()` 方法是否做了参数化查询（`selectionArgs`）
4. 检查 `openFile()` 是否有路径遍历风险（`../` 测试）

### Scoped Storage 影响 (Android 11+)

- `Environment.getExternalStorageDirectory()` 不再可写
- `MediaStore` API 需要通过媒体集合访问
- 应用专属目录 `context.getExternalFilesDir()` 仍可访问
- 检查目标是否使用 `MANAGE_EXTERNAL_STORAGE` 权限申请了所有文件访问

### Android Keystore 交互追踪

Hook 以下入口确认密钥使用情况：

```javascript
Java.perform(function () {
  var KS = Java.use("java.security.KeyStore");
  KS.getKey.overload("java.lang.String", "[C").implementation = function (alias, pwd) {
    console.log("[KS+getKey] alias=" + alias);
    return this.getKey(alias, pwd);
  };
  var Cipher = Java.use("javax.crypto.Cipher");
  Cipher.init.overload("int", "java.security.Key").implementation = function (op, key) {
    console.log("[Cipher+init] opmode=" + op + " key=" + key);
    return this.init(op, key);
  };
});
```

## 常见分歧处理

- SP 文件存在但内容为空：检查是否使用了 EncryptedSharedPreferences 或运行时才写入
- MMKV 初始化失败：确认 `MMKV.initialize()` 的 rootDir 参数，hook `MMKV.defaultMMKV` 确认 mmap 文件路径
- ContentProvider 无法从外部访问：检查 `path-permission` 的 readPermission / writePermission 限制
- 数据库文件加密（SQLCipher）：hook `net.sqlcipher.database.SQLiteDatabase` 而非原生类

## 最小交付

- `run/storage-ipc-notes.md`：存储机制清单、敏感字段列表、IPC 入口清单
- `run/storage-hooks.js`：针对目标定制的存储 hook 脚本
- 报告中的存储与 IPC 证据：明文凭证截图、IPC 攻击面评估、加密缺失结论
