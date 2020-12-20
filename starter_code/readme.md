# p2p下载

## 运行
- 需修改hupsim.pl,将首行perl位置改为系统perl所在位置，本实验中为/usr/bin/perl

## 全局变量
- g_connection数组，记录连接状态，成员变量:

    struct sockaddr_in from //对应peer地址

    int state //state = 0 no connection, state = 1 connected

    clock_t timer //计时器

    int duplicate //重复确认

    char chunk[20] //hash

    int id //对应id

    int type //type 0 receive, type 1 send

    long offset //记录偏移量

    unsigned int next_pack_expected

    unsigned int LastPacketAcked

    unsigned int LastPacketSent

    unsigned int LastPacketAvailable

- g_connected 连接数

- g_chunks数组， 记录hash及对应地址

    char chunk[20] hash值

    struct sockaddr_in peers[30] 记录peer的地址

    int index; // peer数量

    int id; 对应id

    int completed; // 0为接收， 1以接受， 2正在接收
    
- g_chunkNum chunk数量


## 接收
- 接受get指令，在process_get(char *chunkfile, char *outputfile, bt_config_t *config, int sock)函数中发送WHOHAS package，receive_IHAVE_pack(int sock)函数停止5秒钟接受IHAVE package，创建g_chunk数组， 为所有chunk记录对应的所有peer， 创建g_connection, 使g_connected.
- 根据chunkfile进行遍历，从每个chunk_peer_t的地址列表中寻找未连接的端口，发送get请求,将completed 状态设为2， 表示已经开始获取但未接收完成，如果失败或者收到denied包，则匹配下一个地址。
- 在get阶段以1s作为重传时间，通过收包时间计算RTT时间，以RTT最大值作为重传时间
- 记录每个连接，用state确定状态，timer记时， 对每个超时的send的连接发送数据
- 开始接收数据包，遍历connection根据地址确定peer，为对应文件写入数据
- 使用非阻塞式select
- 当收到seq为最后一个包序号时，关闭连接

## 发包
- 收到whohas包send_IHAVE_pack(int sock, struct sockaddr_in from, bt_config_t *config, WHOHAS_pack_t *curr)发送IHAVE包
- 收到get包，确认未达连接上限，send_data(int sock, struct sockaddr_in from, bt_config_t *config, get_pack_t *get_pack)发送第一个data包，同时建立g_connection,将type设为1，表示发送端。
- 接收ack，3个重复ack重新发窗口内所有包，如果ack_seq大于g_connection对应ack，则更新ack，根据窗口补发发包
- 当收到ack为最后一个包序号时，关闭连接

## 多线程
- 使用g_connection数组实现， 当g_connected小于最大连接数目时，则遍历前max_con个g_connection，建立接收或发送连接
- 崩溃或结束时state设为0，用于下次建立连接

## robust
- 为每个receive连接记录时间，当时间超过60s未响应则视为崩溃，重新发送whohas包, 接受并更新g_chunk，对未连接的重新设置连接
- get包设置3次重传为上限，超过则认为get失败，collapse