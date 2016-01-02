/*
 * ginic.i (the SWIG interface for GINI)
 * AUTHOR: Haowei Shi
 * DATE: October 01, 2014
 *
 */

%module GINIC
%inline %{
    #include <sys/types.h>
    #include "grouter.h"
    #include "message.h"
    #include "arp.h"
    #include "gnet.h"
    #include "ip.h"
    #include "packetcore.h"
    #include "routetable.h"
    #include "mtu.h"
    #define MAX_IPREVLENGTH_ICMP            50       // maximum previous header sent back
    #define MAX_MESSAGE_SIZE                sizeof(gpacket_t)
    #define uchar unsigned char
    #define ushort unsigned short


    extern pktcore_t *pcore;
    extern route_entry_t route_tbl[MAX_ROUTES]; // routing table
    extern mtu_entry_t MTU_tbl[MAX_MTU]; // MTU table
    extern interface_array_t netarray;
    extern devicearray_t devarray;
    extern arp_entry_t arp_cache[ARP_CACHE_SIZE];
    extern arp_entry_t ARPtable[MAX_ARP];		                // ARP table
    extern arp_buffer_entry_t ARPbuffer[MAX_ARP_BUFFERS];   	// ARP buffer for unresolved packets
    extern int tbl_replace_indx;            // overwrite this element if no free space in ARP table
    extern int buf_replace_indx;            // overwrite this element if no free space in ARP buffer
    
    /* TODO: simplify..*/
    PyObject * IPPayload(gpacket_t * gpacket)
    {
        int payload = sizeof (gpacket->data.data);
        int gheader = sizeof (gpacket_t) - payload;
        int len_payload = sizeof (*gpacket) - gheader - sizeof (ip_packet_t);
        ip_packet_t *ip_pkt = (ip_packet_t *) gpacket->data.data;
        return PyString_FromStringAndSize((char *) (ip_pkt + 1), len_payload);
    }
    /* helper function for gpacket */
    gpacket_t * createGPacket(PyObject * pkt) 
    {
        void * pktString = PyString_AsString(pkt);
        gpacket_t *gpkt = (gpacket_t *)pktString;
        return gpkt;

    }
    /* returns a new packet with only ip_payload changed */
    gpacket_t * assembleWithIPPayload(PyObject * gpacket_py, PyObject * payload) 
    {
        void * pktString = PyString_AsString(payload);
        gpacket_t *gpkt = (gpacket_t *)PyString_AsString(gpacket_py);
        memcpy((gpkt->data.data)+sizeof (ip_packet_t), PyString_AsString(payload), PyString_Size(payload));        
        return gpkt;

    }
        gpacket_t * createGPacketWithPacket(PyObject * packet)
    {
        void * pktString = PyString_AsString(packet);
        gpacket_t *gpkt = (gpacket_t *) calloc(1, sizeof(gpacket_t));
        memcpy(&(gpkt->data.data), PyString_AsString(packet), PyString_Size(packet));
        return gpkt;
    }
    /* returns a gpacket with ip_payload as input */
    gpacket_t * createGPacketWithIPPayload(PyObject * payload) 
    {
        void * pktString = PyString_AsString(payload);
        gpacket_t *gpkt = (gpacket_t *) calloc(1, sizeof (gpacket_t));
        memcpy((gpkt->data.data)+sizeof (ip_packet_t), PyString_AsString(payload), PyString_Size(payload));
        return gpkt;
    }
    
    PyObject *getGPacketMetaheaderLen(){
        return PyLong_FromSize_t(MAX_MESSAGE_SIZE - DEFAULT_MTU + sizeof(ip_packet_t));
    }

    PyObject* getGPacketString(gpacket_t * gpacket) {
        printf("[getGPacketString]size: %d\n", sizeof (*gpacket) - sizeof(pkt_frame_t));
        return PyString_FromStringAndSize((char *) (&(gpacket->data)), sizeof (*gpacket) - sizeof(pkt_frame_t));
    }
    
    
    /* TODO:
     * Helper functions for routing table
     */
    PyObject* findRoute(PyObject* ip)
    {
        
        char tmpbuf[MAX_TMPBUF_LEN];
        uchar* ip_addr = PyString_AsString(ip);
        uchar nxth_ip_addr[4];
        uchar ip_addr_dot[4];
        int interface = 0;
        Dot2IP(ip_addr, ip_addr_dot);
        printf("py: %s %s\n", ip_addr, tmpbuf);
        if (findRouteEntry(route_tbl, ip_addr_dot,
                       nxth_ip_addr,
                       &interface) == EXIT_FAILURE)
        {
            return Py_None;
        }
        return Py_BuildValue("si", IP2Dot(tmpbuf, nxth_ip_addr), interface);
    }
    void showRouteTable()
    {
        printRouteTable(route_tbl);
    }
    
    void addRoute(PyObject *network, PyObject* netmask, PyObject* next_hop, PyObject* interface){
        uchar nwork[4];
        uchar nmask[4];
        uchar nhop[4];
        int iface = PyInt_AsLong(interface);
        Dot2IP(PyString_AsString(network), nwork);
        Dot2IP(PyString_AsString(netmask), nmask);
        Dot2IP(PyString_AsString(next_hop), nhop);
        addRouteEntry(route_tbl, nwork, nmask, nhop, interface);
    }
    


%}

typedef struct _pkt_data_t {

    struct {
        uchar dst[6]; // destination host's MAC address (filled by gnet)
        uchar src[6]; // source host's MAC address (filled by gnet)
        ushort prot; // protocol field
    } header;
    uchar data[DEFAULT_MTU]; //payload  
} pkt_data_t;

typedef struct _label_t {
    ushort prot;
    ushort process; //0 un process  1 processed 2 invalid
} label_t;
// frame wrapping every packet... GINI specific (GINI metadata)

typedef struct _pkt_frame_t {
    int src_interface; // incoming interface number; filled in by gnet?
    uchar src_ip_addr[4]; // source IP address; required for ARP, IP, gnet
    uchar src_hw_addr[6]; // source MAC address; required for ARP, filled by gnet
    int dst_interface; // outgoing interface, required by gnet; filled in by IP, ARP
    uchar nxth_ip_addr[4]; // destination interface IP address; required by ARP, filled IP
    int arp_valid;
    int arp_bcast;
    label_t label[8]; // label for flow table; required by packet core, filled by each protoco process
} pkt_frame_t;

typedef struct _gpacket_t {
    pkt_frame_t frame;
    pkt_data_t data;
} gpacket_t;


%typemap(in) (uchar *) {
    $1 = PyString_AsString($input);
}

/* 
 * Interface for existing functions in gRouter
 * 
 */


/* IP output function */
int IPOutgoingPacket(gpacket_t *out_gpkt, uchar *dst_ip, int size, int newflag, int src_prot);

/* Routing table manipulation */
void addRouteEntry(route_entry_t route_tbl[], uchar* nwork, uchar* nmask, uchar* nhop, int interface);

%typemap(in) (route_entry_t route_tbl[], uchar* nwork, uchar* nmask, uchar* nhop, int interface) {
    $1 = route_tbl;
    $2 = PyString_AsString($input);
    $3 = PyString_AsString($input);
    $4 = PyString_AsString($input);
    $5 = PyInt_AsLong($input);
}