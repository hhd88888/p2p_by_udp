# p2p下载

## 多线程

- 接受get指令，在process_getprocess_get(char *chunkfile, char *outputfile, bt_config_t *config, int sock)函数中发送WHOHAS package，然后停止5秒钟接受IHAVE package
- 根据chunk进行存储，chunk_peer_t记录chunk以及包含有chunk的所有peer地址
- 根据chunkfile进行遍历，从每个chunk_peer_t的地址列表中寻找未连接的端口，发送get请求,将completed 状态设为2， 表示已经开始获取但未接收完成，如果失败或者收到denied包，则匹配下一个地址。
- 开始接受，根据地址确定peer，为对应文件写入数据
- 在get阶段以1s作为重传时间，通过收包时间计算RTT时间，以4倍RTT最大值作为重传时间
- 使用非阻塞式select
- 记录每个连接，用state确定状态，timer记时， 对每个超时的send的连接发送数据

## robust
- 为每个receive连接记录时间，当时间超过60s未响应则视为崩溃，重新发送whohas包, 接受并更新g_chunk，对未连接的重新设置连接
- get包设置3次重传为上限，超过则认为get失败