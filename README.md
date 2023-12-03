# sabanote

[日本語](#説明)

## Description

**sabanote** runs as a plug-in for the agent of the SaaS monitoring service [Mackerel](https://mackerel.io), and when a relevant alert occurs, it records information on the heavily loaded processes (or any command output) on the host around that time to [Graph Annotation](https://mackerel.io/docs/entry/howto/view-graphs#graph-annotations).

![](graph.png)

## Synopsis
```
check-sabanote -m MONITOR_ID -s SERVICE -r ROLE [other options...]
```

The minimum required specification is the monitoring rule ID (`-m`) to be monitored, the service name (`-s`) and role name (`-r`) to which graph annotations are posted.

Multiple monitoring rule IDs and roles can be specified.

```
check-sabanote -m MONITOR_ID1 -m MONITOR_ID2 -s SERVICE -r ROLE1 -r ROLE2
```

The monitoring rule ID is the `<XXXXXXXX>` part of the URL `https://mackerel.io/my/monitors/<XXXXXXXX>` when opening the monitoring rule page. You can also look it up with `mkr monitors`.

This plugin logs the collection of process information (or the result of any command execution) to a simple database each time it is run (every minute by default).

It also periodically queries the Mackerel server for alerts and writes the information in the database as graph annotations when the following conditions are met:

- The alert's monitoring rule ID matches, and the host ID in the alert also matches.
- The monitoring rule ID of the alert matches and the host ID is not specified in the alert. (e.g., external monitoring)
- Check monitoring and connectivity alerts with matching host IDs.

By default, information is written to the graph annotation every minute from 3 minutes before the alert time to 1 minute after the alert time.

The content written by default depends on the operating system.

- Linux and macOS: Top 20 results for CPU or memory usage based on the `ps` command
- Windows: Top 20 results for CPU time or memory usage based on the `Get-Process` PowerShell command

## Setting for mackerel-agent
This plug-in can be installed with the `mkr` command.

```
sudo mkr plugin install github.com/kmuto/sabanote
```

Describe the plugin configuration in your mackerel-agent.conf.

```
[plugin.checks.sabanote]
command = ["check-sabanote", "-m", "MONITOR_ID", "-s", "SERVICE_NAME", "-r", "ROLE_NAME"]
```

## Usage
### Options
- `--monitor MONITOR_ID, -m MONITOR_ID`: target monitoring rule ID; multiple monitoring rules can be targeted by specifying multiple `-m` options.
- `--service SERVICE, -s SERVICE`: Name of the service to which graph annotation is posted.
- `--role ROLE, -r ROLE`: Name of the role to which graph annotation is posted. Multiple roles can be targeted by specifying multiple `-r` options (but not across services).
- `--host HOST_ID, -H HOST_ID`: Target host ID.
- `--title TITLE`: Title for the graph annotation. Default is `Host <HOST> status when <ALERT> is alerted (<TIME>)`, where `<HOST>` is replaced by the host ID, `<ALERT>` by the alert ID, and `<TIME>` by the time of occurrence.
- `--mem`: When displaying the top processes, order them by memory usage. If not specified, they are ordered by CPU usage.
- `--cmd CMD_PATH, -c CMD_PATH`: Execute any command instead of process information and use its standard output for graph annotation.
- `--state DIR`: Folder to place the simple database.
- `--before MINUTES`: how many minutes before the alert are to be written to graph annotations, from 0 to 5 (default 3).
- `--after MINUTES`: the number of minutes after the alert that should be written to the graph annotation, from 0 to 5 (default: 1).
- `--alert-frequency MINUTES`: The interval (in minutes) to query for the existence of an alert, from 2 to 30 (default is 5). If 0 is specified, no alerts are queried.
- `--delay SECONDS`: The number of seconds to wait before executing a command to get process information or execute any command, from 0 to 29 (default is 0).
- `--verbose`: Print debug logs for each stage to standard error.
- `--help, -h`: Display help messages.
- `--version`: display the version.


### Hints
There is a timeout limit for running the mackerel-agent plugin. Basically, you need to be careful to finish the process within 30 seconds.

Specifying a host ID with the `-H` option is basically unnecessary, since the ID is automatically taken from the environment where mackerel-agent is installed. Specify it when you want to target a different host ID.

Command execution with `-c` accepts only a single executable file, and no options can be specified. If you need options, you should use a script that wraps the command with options. Also, due to restrictions on graph annotations, the file size must be limited to 1KB.

The `--delay` execution delay is a workaround for when Windows WMI access is too busy to retrieve. Be careful also about the timeout limit for plugin execution.

The simple database will continue to record the connectivity error, but only up to 6 hours in the past.

The check plugin itself returns only OK or Unknown (e.g., command execution failure or database write malformed).

## License
© 2023 Kenshi Muto

Apache License (see LICENSE file)

---

## 説明

**sabanote**（さばのて）は、SaaS 型監視サービス [Mackerel](https://ja.mackerel.io) のエージェントのプラグインとして動作し、関係するアラートが発生したときに、その時間付近のホスト上の高負荷なプロセス情報または任意のコマンド実行結果を[グラフアノテーション](https://mackerel.io/ja/docs/entry/howto/view-graphs#graph-annotations)に記録します。

![](graph.png)

## 概要
```
check-sabanote -m MONITOR_ID -s SERVICE -r ROLE [その他のオプション]
```

最低限必要な指定は、監視対象の監視ルール ID（`-m`）、グラフアノテーションを投稿する対象のサービス名（`-s`）およびロール名（`-r`）です。

監視ルール ID とロールは複数指定できます。

```
check-sabanote -m MONITOR_ID1 -m MONITOR_ID2 -s SERVICE -r ROLE1 -r ROLE2
```

監視ルール ID は、監視ルールを開いたときの URL `https://mackerel.io/my/monitors/<XXXXXXXX>` の `<XXXXXXXX>` の部分です。`mkr monitors` で調べることもできます。

このプラグインは、実行のたびにプロセス情報の収集（または任意のコマンド実行結果）をシンプルなデータベースに記録します（デフォルトのプラグイン設定では 1 分ごと）。

さらに定期的に Mackerel のサーバーにアラートが存在するかを問い合わせ、以下の条件に合致するときにデータベース内の情報をグラフアノテーションとして書き込みます。

- アラートの監視ルール ID に一致し、かつアラートにホスト ID が記載されていてそれも一致する
- アラートの監視ルール ID に一致し、かつアラートにホスト ID の記載がない（外形監視など）
- チェック監視や connectivity によるアラートで、ホスト ID が一致している

デフォルトではアラート発生時刻の3分前〜アラート発生時刻の1分後までの各分ごとにグラフアノテーションが書き込まれます。

デフォルトで書き込まれる内容は OS によって異なります。

- Linux・macOS：`ps` コマンドに基づく、CPU またはメモリ使用量の上位20位までの結果
- Windows：`Get-Process` PowerShell コマンドに基づく、CPU 消費時間またはメモリ使用量の上位20位までの結果

## mackerel-agentでの設定
プラグインは `mkr` コマンドでインストールできます。

```
sudo mkr plugin install github.com/kmuto/sabanote
```

mackerel-agent.conf にプラグインの設定を記述してください。

```
[plugin.checks.sabanote]
command = ["check-sabanote", "-m", "MONITOR_ID", "-s", "SERVICE_NAME", "-r", "ROLE_NAME"]
```

## 使い方
### オプション
- `--monitor MONITOR_ID, -m MONITOR_ID`：対象の監視ルール ID。`-m` オプションを複数指定することで、複数の監視ルールを対象にできる
- `--service SERVICE, -s SERVICE`：グラフアノテーションの投稿先のサービス名
-  `--role ROLE, -r ROLE`：グラフアノテーションの投稿先のロール名。`-r` オプションを複数指定することで、複数のロールを対象にできる（ただし、サービスをまたがって指定することはできない）
- `--host HOST_ID, -H HOST_ID`：対象のホスト ID
-  `--title TITLE`：グラフアノテーションのタイトル。デフォルトは `Host <HOST> status when <ALERT> is alerted (<TIME>)` で、`<HOST>` はホスト ID、`<ALERT>` はアラート ID、`<TIME>` は発生時刻に置き換えられる
- `--mem`：上位プロセスを表示する際に、メモリ使用量の順に並べる。指定しない場合は CPU 使用率順になる
- `--cmd CMD_PATH, -c CMD_PATH`：プロセス情報の代わりに、任意のコマンドを実行し、その標準出力の内容をグラフアノテーションで使うようにする
- `--state DIR`：簡易データベースを配置するフォルダ
- `--before MINUTES`：アラートが発生してから何分前までの記録をグラフアノテーションに書き込むか。0〜5 で指定し、デフォルトは 3
- `--after MINUTES`：アラートが発生してから何分後までの記録をグラフアノテーションに書き込むか。0〜5 で指定し、デフォルトは 1
- `--alert-frequency MINUTES`：アラートが存在するか問い合わせる際の実行間隔（分）。2〜30 で指定し、デフォルトは 5。また、0 を指定するとアラートの存在を問い合わせない
- `--delay SECONDS`：プロセス情報の取得または任意のコマンドを実行する際の実行前待ち時間（秒）。0〜29 で指定し、デフォルトは 0
- `--verbose`：各段階のデバッグログを標準エラーに書き出す
- `--help, -h`：オプションヘルプを表示する
- `--version`：バージョンを表示する

### オプションのヒント
mackerel-agent のプラグインの実行にはタイムアウトの制限があります。基本的に 30 秒以内で処理が終わるように注意する必要があります。

`-H` オプションによるホスト ID 指定は、mackerel-agent がインストールされている環境ではその ID が自動で使われるので基本的には不要です。あえて別のものを対象にしたいときに指定してください。

`-c` によるコマンド実行は、単一の実行ファイルのみを受け付け、オプションは指定できません。オプションを含めてラップするようなスクリプトにするなどで対処してください。また、グラフアノテーションの制約上、1KB までに収める必要があります。

`--delay` による実行遅延は、Windows の WMI アクセスが集中して取得できない場合への対策です。プラグインの実行のタイムアウトの制限にも注意してください。

connectivity エラーが発生している状態でも簡易データベースには記録が継続していますが、保持されるのは 6 時間前までです。

このチェックプラグイン自体は OK または Unknown（コマンド実行の失敗やデータベース書き込み不正など）のみを返します。

## ライセンス
© 2023 Kenshi Muto

Apache License (LICENSE ファイル参照)
