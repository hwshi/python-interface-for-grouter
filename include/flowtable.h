/*
 * flowtable.h (include file for the flow table)
 * AUTHOR: Haowei Shi
 * DATE: October 01, 2014
 *
 */

#ifndef __FLOW_TABLE_H__
#define __FLOW_TABLE_H__
#define MAX_ENTRY_NUMBER 50
#define MAX_ENTRY_SIZE 4
#define FLOW_NOT_MATCH 0
#define FLOW_MATCH 1
#include <slack/std.h>
#include <slack/map.h>
#include <slack/list.h>
#include <pthread.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>

#include "message.h"
#include "grouter.h"
#include "simplequeue.h"
#include "qdisc.h"
#include "protocols.h"
#include "ip.h"
#include "arp.h"
#include "icmp.h"
//#include "packetcore.h"

#define OFP_ETH_ALEN 6

//tpye of entry
#define CLASSICAL 1
#define OPENFLOW 2

//type of language
#define C_FUNCTION 0
#define PYTHON_FUNCTION 1
//typedef struct _tcp_udp_header_t
//{
//    ushort src_port;
//    ushort dst_port;
//}tcp_udp_header_t;
//config infor
typedef struct _module_config_t
{
    char *name;
    ushort protocol;
    void *processor;
    void *command;
    char *command_str;
    char *shelp;
    char *usage;
    char *lhelp;
} module_config_t;

//flow table
typedef struct _ftentry_t
{

    ushort is_empty;
    ushort language;
    ushort ip_protocol_type;
    void *action;
    
} ftentry_t;

typedef struct _flowtable_t
{
    int num;
    ftentry_t entry[MAX_ENTRY_NUMBER];
} flowtable_t;
void *decisionProcessor(void *pc);
int addEntry(flowtable_t *flowtable, int type, ushort language, module_config_t *config);
flowtable_t *initFlowTable();
int defaultProtocol(flowtable_t *flowtable, ushort prot, void *function);
int addProtocol(flowtable_t *flowtable, ushort language, char *protname);
int addModule(flowtable_t *flowtable, ushort language, char *mod_name);
int addPyModule(flowtable_t *flowtable, char *mod_name);
int addCModule(flowtable_t *flowtable, char *mod_name);

ftentry_t *checkFlowTable(flowtable_t *flowtable, gpacket_t *pkt);
void printFlowTable(flowtable_t *flowtable);

char *Name2ConfigName(char *tmpbuff, char *mod_name);
void printConfigInfo(module_config_t *config);

#endif