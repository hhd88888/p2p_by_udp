# p2p下载

## 多线程

- 接受get指令，在process_getprocess_get(char *chunkfile, char *outputfile, bt_config_t *config, int sock)函数中发送WHOHAS package，然后停止5秒钟接受IHAVE package
- 根据chunk进行存储，chunk_peer_t记录chunk以及包含有chunk的所有peer地址
- 根据chunkfile进行遍历，从每个chunk_peer_t的地址列表中寻找未连接的端口，发送get请求，如果失败或者收到denied包，则匹配下一个地址。
- 开始接受，根据地址确定peer，为对应文件写入
- 