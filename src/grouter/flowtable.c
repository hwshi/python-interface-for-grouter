/*
 * flowtable.c (the flowtable for packet core)
 * AUTHOR: Haowei Shi
 * DATE: October 01, 2014
 *
 */

#include "ginic_wrap.c"
#include "flowtable.h"
#include "Python.h"
#include <sys/types.h>

void *decisionProcessor(void *pc)
{
    pktcore_t *pcore = (pktcore_t *) pc;
    gpacket_t *in_pkt;
    SWIG_init(); /* Initialize the wrapped GINIC module*/
    int pktsize;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    while (1)
    {
        verbose(2, "[decisionProcessor]:: Waiting for a packet...");
        readQueue(pcore->decisionQ, (void **) &in_pkt, &pktsize);
        pthread_testcancel();
        verbose(2, "[decisionProcessor]:: Got a packet for further processing...");
         /* Classical router processor.*/
        classicalDecisionQProcessor(pcore, in_pkt);
    }
}

flowtable_t *initFlowTable()
{
    verbose(2, "[initFlowTable]:: \n");
    flowtable_t *flowtable = (flowtable_t *) malloc(sizeof (flowtable_t));
    flowtable->num = 0;
    defaultProtocol(flowtable, ARP_PROTOCOL, (void *) ARPProcess);
    defaultProtocol(flowtable, IP_PROTOCOL, (void *) IPIncomingPacket);
    defaultProtocol(flowtable, ICMP_PROTOCOL, (void *) ICMPProcessPacket);
    verbose(2, "[initFlowTable]:: finished size: %d\n", flowtable->num);
    return flowtable;
}

int defaultProtocol(flowtable_t *flowtable, ushort prot, void *function)
{
    verbose(2, "[defaultProtocol]:: Adding default protocol: %hu\n", prot);
    if (flowtable->num < MAX_ENTRY_NUMBER)
    {
        flowtable->entry[flowtable->num].is_empty = 0;
        flowtable->entry[flowtable->num].language = C_FUNCTION;
        flowtable->entry[flowtable->num].ip_protocol_type = prot;
        flowtable->entry[flowtable->num].action = function;
        flowtable->num++;
    }
    else
    {
        verbose(2, "[defaultProtocol]:: Exceed MAX_ENTRY_NUMBER\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int classicalDecisionQProcessor(pktcore_t *pcore, gpacket_t *pkt)
{
    ftentry_t *entry_res = checkFlowTable(pcore->flowtable, pkt);
    int (*processor)(gpacket_t *);
    if (entry_res == NULL)
    {
        printf("[decisionProcessor]:: Cannot find action to given packet...Drop!\n");
        return EXIT_FAILURE;
    }
    else if (entry_res->language == C_FUNCTION)
    {
        verbose(2, "[decisionProcessor]:: Entry found protocol: %#06x C Function: Action: (0x%lx)\n", entry_res->ip_protocol_type, (unsigned long) entry_res->action);
        processor = entry_res->action;
        int nextlabel = (*processor)(pkt);
        if (nextlabel == NULL_PROTOCOL)
            return EXIT_SUCCESS;
        verbose(2, "[decisionProcessor][Ft]New style round");
        labelNext(pkt, entry_res->ip_protocol_type, nextlabel);
        writeQueue(pcore->decisionQ, pkt, sizeof (gpacket_t));
        verbose(2, "[decisionProcessor]:: Wrote back to decision Q...");
    }
    else if (entry_res->language == PYTHON_FUNCTION)
    {
        verbose(2, "[decisionProcessor]:: Entry found protocol: %#06x Python Function: Action: (0x%lx)\n", entry_res->ip_protocol_type, (unsigned long) entry_res->action);

        PyObject * PyActionFun, *PyPkt, *PyFunReturn;
        PyActionFun = entry_res->action;
        PyPkt = SWIG_NewPointerObj((void *) pkt, SWIGTYPE_p__gpacket_t, 1);
        if (PyPkt)
        {
            /*TODO: handle PyReturn for further process*/
            verbose(2, "[decisionProcessor]:: Ready to call Python function");

            printf("[classicalDecisionQProcessor] check lock..\n");
            PyEval_AcquireLock();
            verbose(2, "got the lock\n");
            PyFunReturn = PyObject_CallFunction(PyActionFun, "O", PyPkt);
            printf("[classicalDecisionQProcessor]ready to release lock\n");

            PyEval_ReleaseLock();
            
            CheckPythonError();
        }
    }
}



/* Add a protocol processor with a specified language into flowtable */
int addModule(flowtable_t *flowtable, ushort language, char *mod_name)
{
    verbose(2, "[addModule]Start to add protocol");
    switch (language)
    {
    case PYTHON_FUNCTION:
        if (addPyModule(flowtable, mod_name) == EXIT_SUCCESS)
        {
            verbose(2, "[addModule]Python module: %s added", mod_name);
            return EXIT_SUCCESS;
        }
        else break;
    case C_FUNCTION:
        if (addCModule(flowtable, mod_name) == EXIT_SUCCESS)
        {
            verbose(2, "[addModule]C Module: %s added", mod_name);
            return EXIT_SUCCESS;
        }
        else break;
    }
    CheckPythonError();
    return EXIT_FAILURE;
}

/* Add a protocol processor implemented in Python into flowtable */
int addPyModule(flowtable_t *flowtable, char *mod_name)
{
    PyRun_SimpleString("import sys");
    PyRun_SimpleString("sys.path.append('./')");
    PyObject *PyModule, *PyModuleGlobalDict, *PyFunProcess, *PyFunCommandLine, *PyFunConfig, *PyTupleConfig;
    module_config_t *config = (module_config_t *) calloc(1, sizeof (module_config_t));
    PyModule = PyImport_ImportModule(mod_name);
    if (PyModule)
    {
        PyModuleGlobalDict = PyModule_GetDict(PyModule);
        if (PyModuleGlobalDict)
        {
            config->command = (void *) PyDict_GetItemString(PyModuleGlobalDict, "Command_Line");
            if (config->command == NULL)
                verbose(2, "[addPyModule]PyFunCommandLine is NULL!!\n", PyFunCommandLine);
            /* return a tuple of config info */
            PyFunConfig = PyDict_GetItemString(PyModuleGlobalDict, "Config");
            if (PyFunConfig)
            {
                PyTupleConfig = PyObject_CallFunction(PyFunConfig, NULL);
                verbose(2, "[addPyModule] got config\n");
                PyArg_ParseTuple(PyTupleConfig, "sissss", &config->name, &config->protocol,
                                 &config->command_str, &config->shelp, &config->usage, &config->lhelp);
                verbose(2, "[addPyModule] set config 1\n");
                config->processor = PyDict_GetItemString(PyModuleGlobalDict, "Protocol_Processor"); 
                if (config->processor)
                {
                    printConfigInfo(config);
                    addEntry(flowtable, CLASSICAL, PYTHON_FUNCTION, config); //add protocol into flow table
                    verbose(2, "[addPyModule]:: Python Processor added into flowtable!!!");
                    return EXIT_SUCCESS;
                }
            }
        }
        printf("[addPyModule]:: Failed to get Main Dictionary of module -%s- !\n", mod_name);
        return EXIT_FAILURE;

    }
    printf("[addPyModule]:: Failed to load module -%s- !\n", mod_name);
    return EXIT_FAILURE;
}

/* Add a protocol processor implemented in C into flowtable */
int addCModule(flowtable_t *flowtable, char *mod_name)
{
    // read config info from mod_nameConfig()
    module_config_t *config;
    void *library = NULL;
    module_config_t * (*config_fun)();
    library = dlopen(mod_name, RTLD_LAZY); //RTLD_LAZY  RTLD_NOW
    if (library)
    {
        char tmpbuff[20];
        //config_fun = dlsym(library, Name2ConfigName(tmpbuff, mod_name));
        config_fun = dlsym(library, Name2ConfigName(tmpbuff, "udp2"));
        if (config_fun)
            config = config_fun();
        printConfigInfo(config);
        if (addEntry(flowtable, CLASSICAL, C_FUNCTION, config) == EXIT_SUCCESS)
            return EXIT_SUCCESS;
    }
    else
    {
        printf("%s \n", dlerror());
        return EXIT_FAILURE;
    }
}

/* add new protocol into flowtable*/
int addEntry(flowtable_t *flowtable, int type, ushort language, module_config_t *config)
{

    verbose(2, "[addEntry]:: \n");

    if (type == CLASSICAL)
    {
        verbose(2, "[addEntry]:: Adding a classical entry\n");
        if (flowtable->num < MAX_ENTRY_NUMBER)
        {
            flowtable->entry[flowtable->num].is_empty = 0;
            flowtable->entry[flowtable->num].language = language;
            flowtable->entry[flowtable->num].ip_protocol_type = config->protocol;
            flowtable->entry[flowtable->num].action = config->processor;
            registerCLI(config->command_str, config->command, language, config->shelp, config->usage, config->lhelp);
            verbose(2, "[addPyModule]:: Command < %s >registered\n", config->command_str);
            flowtable->num++;
            return EXIT_SUCCESS;
        }
        else
        {
            verbose(2, "[addEntry]:: flowtable is full...Exit with failure\n");
            return EXIT_FAILURE;
        }
    }
    else if (type == OPENFLOW)
    {
        verbose(2, "[addEntry]:: Adding a openflow entry\n");
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}


char *Name2ConfigName(char *tmpbuff, char *mod_name)
{
    strcpy(tmpbuff, mod_name);
    strcat(tmpbuff, "Config");
    return tmpbuff;
}

void printConfigInfo(module_config_t *config)
{
    printf("----    Config Information  ----\n");
    printf("module name :       %s\n", config->name);
    printf("protocol    :       %#06x\n", config->protocol);
    printf("processor   :       %p\n", config->processor);
    printf("command     :       %p\n", config->command);
    printf("shelp       :       %s\n", config->shelp);
    printf("usage       :       %s\n", config->usage);
    printf("lhelp       :       %s\n", config->lhelp);
    printf("----       End of Config    ----\n");
}
// use short for result count?



ftentry_t *checkFlowTable(flowtable_t *flowtable, gpacket_t *pkt)
{
    //find the protocol label
    int i, j, fromUpper = 0, prot = NULL_PROTOCOL;
    verbose(2, "[checkFlowTable]:: Search protocol(EtherType): %#06x\n", ntohs(pkt->data.header.prot));
    for (i = 0; i < 8; i++)
    {
        if (pkt->frame.label[i].prot != NULL_PROTOCOL && pkt->frame.label[i].process == 0)
        {
            prot = pkt->frame.label[i].prot;
            verbose(2, "[checkFlowTable]:: Found Next protocol: %hu in pkt: %hu\n", prot, ntohs(pkt->data.header.prot));
            if (pkt->frame.label[i + 1].prot == 1)
            {
                verbose(2, "[checkFlowTable]:: From Upper Layer of %hu", prot);
                fromUpper = 1;
            }
            break;
        }

    }
    if (prot == NULL_PROTOCOL)
    {
        verbose(2, "[checkFlowTable]::Didn't find any protocol in FT!");
        return NULL;
    }
    for (j = 0; j < flowtable->num; j++)
    {
        //verbose(2  , "[checkFlowTable]::Checking for entry");
        if (flowtable->entry[j].ip_protocol_type == prot)
        {
            verbose(2, "[checkFlowTable]:: Entry found protocol(entry): %#06x\n", flowtable->entry[j].ip_protocol_type);
            return &(flowtable->entry[j]);
        }
    }
    verbose(2, "Failed finding a entry!\n");
    return NULL;
}



void printFlowTable(flowtable_t *flowtable)
{
    printf("--  Flow Table Status  --\n");
    printf("Size: %d\n", flowtable->num);
    printf("Details: \n");
    int i;
    for (i = 0; i < flowtable->num; i++)
    {
        printf("\t[%d]protocol: %d language: %d :: action %p\n",
               i,
               flowtable->entry[i].ip_protocol_type,
               flowtable->entry[i].language,
               flowtable->entry[i].action);
    }
    printf("-- End of Flow Table --\n");
}
