/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

int seq=0;


Buffer ArrayToBuffer(uint8_t* arr, int n){
  std::vector<uint8_t> vec;
  for(int i=0;i<n;i++){
    vec.push_back(arr[i]);
  }
  return vec;
}

void AppendToEnd(Buffer& building,void* _arr,int n){
  uint8_t* arr=reinterpret_cast<uint8_t*>(_arr);
  for(int i=0;i<n;i++){
    building.push_back(arr[i]);
  }
  return;
}



void SimpleRouter::SendPacketWithAutoARP(Buffer& packet){
  uint8_t* pkt=packet.data();
  ethernet_hdr* mac_header=(ethernet_hdr*)pkt;
  uint8_t* ip_pkt=pkt+14;
  ip_hdr* ip_head=(ip_hdr*)(ip_pkt);
  printf("start looking up ");
  std::cout<<ipToString(ip_head->ip_dst)<<"====================="<<std::endl;
  RoutingTableEntry result=m_routingTable.lookup(ip_head->ip_dst);
  printf("about to send==========\n");
  print_hdrs(packet);
  const Interface* outface = findIfaceByName(result.ifName);
  if(result.gw==0){ //default gateway
    result.gw=ip_head->ip_dst;
    std::cout<<"gw==0 "<<ipToString(result.gw)<<std::endl;
  }
  if(result.gw!=ip_head->ip_dst){
    SendICMPPkt(ip_head, outface, 3, 1);
  }
  auto arp_cache_entry=m_arp.lookup(result.gw,false);
  printf("look up end~\n");
  if(arp_cache_entry==nullptr){  //no entry, use arp
    printf("no cache\n");
    std::cout<<"qR mae "<<ipToString(result.gw)<<std::endl;
    m_arp.queueRequest(result.gw,packet,result.ifName,false);
    std::cout<<"qR go "<<ipToString(result.gw)<<std::endl;
  }
  else{
    printf("has cache\n");
    Buffer dest_mac=arp_cache_entry->mac;
    
    memcpy(mac_header->ether_dhost,dest_mac.data(),6);
    memcpy(mac_header->ether_shost,outface->addr.data(),6);
    sendPacket(packet,result.ifName);
  }
  printf("out   =================\n");
}

void SimpleRouter::SendICMPPkt(ip_hdr* ip_head, const Interface* outface, int icmp_type, int icmp_code)
{
        icmp_t3_hdr icmp_t3_header;
        icmp_t3_header.icmp_type=icmp_type;
        icmp_t3_header.icmp_code=icmp_code;
        icmp_t3_header.unused=0;
        icmp_t3_header.icmp_sum=0;
        icmp_t3_header.next_mtu=0;
        memcpy(icmp_t3_header.data,(uint8_t*)ip_head,ICMP_DATA_SIZE);
        icmp_t3_header.icmp_sum=cksum((const void*)&icmp_t3_header,sizeof(icmp_t3_hdr));

        ip_head->ip_hl=5;
        ip_head->ip_v=4;
        ip_head->ip_len=htons(sizeof(ip_hdr)+sizeof(icmp_t3_hdr));
        ip_head->ip_sum=0;
        ip_head->ip_ttl=64;
        ip_head->ip_dst=ip_head->ip_src;
        ip_head->ip_src=outface->ip;
        ip_head->ip_p=ip_protocol_icmp;
        ip_head->ip_sum=cksum((const void*)ip_head,20);
        ethernet_hdr wrapper_icmpreply;
        wrapper_icmpreply.ether_type=htons(ethertype_ip);

        Buffer icmpreply=ArrayToBuffer((uint8_t*)&wrapper_icmpreply,sizeof(ethernet_hdr));
        AppendToEnd(icmpreply,(void*)ip_head,sizeof(ip_hdr));
        AppendToEnd(icmpreply,(void*)&icmp_t3_header,sizeof(icmp_t3_hdr));

        SendPacketWithAutoARP(icmpreply);
  }

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr<<"seq "<<seq++<<std::endl;
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  //std::cerr << getRoutingTable() << std::endl;
  

  // FILL THIS IN
  const uint8_t* pkt=packet.data();
  ethernet_hdr* mac_header=(ethernet_hdr*)pkt;
  
  Buffer dest_mac=ArrayToBuffer(mac_header->ether_dhost,6);

  std::string dest_mac_string=macToString(dest_mac);
  Buffer src_mac=ArrayToBuffer(mac_header->ether_shost,6);
  std::cerr<<macToString(src_mac)<<" "<<dest_mac_string<<std::endl;
  std::cerr<<"out mac test"<<std::endl;
  
  if(dest_mac_string!=macToString(iface->addr) && dest_mac_string!="ff:ff:ff:ff:ff:ff") return; //wheter to deal with this pkt
  print_hdrs(packet);
  switch (htons(mac_header->ether_type))
  {

    case ethertype_arp:
    {
      printf("in arp\n");
      const uint8_t* arp_pkt=pkt+sizeof(ethernet_hdr);
      arp_hdr* arp_head=(arp_hdr*)arp_pkt;
      if(arp_head->arp_op==htons(arp_op_request) && arp_head->arp_tip==iface->ip){
          Buffer arp_reply_ether;

          ethernet_hdr reply_eth_head;
          memcpy(reply_eth_head.ether_dhost,mac_header->ether_shost,6);
          memcpy(reply_eth_head.ether_shost,iface->addr.data(),6);
          reply_eth_head.ether_type=htons(ethertype_arp);
          AppendToEnd(arp_reply_ether,(void*)&reply_eth_head,sizeof(reply_eth_head));

          arp_hdr reply_apr_head;
          reply_apr_head.arp_hrd=htons(arp_hrd_ethernet);
          reply_apr_head.arp_pro=htons(ethertype_ip);
          reply_apr_head.arp_hln=6;
          reply_apr_head.arp_pln=4;
          reply_apr_head.arp_op=htons(2);
          memcpy(reply_apr_head.arp_sha,iface->addr.data(),6);
          reply_apr_head.arp_sip=iface->ip;
          memcpy(reply_apr_head.arp_tha,mac_header->ether_shost,6);
          reply_apr_head.arp_tip=arp_head->arp_sip;
          AppendToEnd(arp_reply_ether,(void*)&reply_apr_head,sizeof(reply_apr_head));
          sendPacket(arp_reply_ether,inIface);
      }
      else if(arp_head->arp_op==htons(arp_op_reply)){
          Buffer dest_mac= ArrayToBuffer(arp_head->arp_sha,6);
          auto satisfied_request=m_arp.insertArpEntry(dest_mac,arp_head->arp_sip);
          if(satisfied_request) 
          {
            for(auto& request: satisfied_request->packets){
              Buffer reply_pkt=request.packet;
              std::string outface_str=request.iface;
              ethernet_hdr* out_mac_header=(ethernet_hdr*)(reply_pkt.data());
              const Interface* outface = findIfaceByName(outface_str);
              memcpy(out_mac_header->ether_dhost,dest_mac.data(),6);
              memcpy(out_mac_header->ether_shost,outface->addr.data(),6);
              sendPacket(reply_pkt,outface_str);
              printf("<<<<<<<<<< ARP reply release >>>>>>>>\n");

              print_hdrs(reply_pkt);
              printf("<<<<<<<<<< ARP reply end >>>>>>>>\n");
            }

            m_arp.removeRequest(satisfied_request);  //不为nullptr
          } 
      }
      
      break;
    }

    case ethertype_ip:
    {
      printf("in ip\n");
      const uint8_t* ip_pkt=pkt+sizeof(ethernet_hdr);
      if(packet.size()-sizeof(ethernet_hdr)<=sizeof(ip_hdr)) return;

      ip_hdr* ip_head=(ip_hdr*)(ip_pkt);
      uint16_t original_checksum=ip_head->ip_sum;
      ip_head->ip_sum=0;
      uint16_t checksum_calc=cksum((const void*)ip_head,20);   //??
//?
      printf("ip here with cksum %d\n",checksum_calc);
      //printf("ip here with cksum unhtons %d\n",cksum((const void*)ip_head,20));

      if(original_checksum!=checksum_calc) return; //discard

      printf("pass cksum\n");

      if((ip_head->ip_p!=ip_protocol_icmp)&&(findIfaceByIp(ip_head->ip_dst))){
              printf("ip is router, send port unreachable\n");
              ip_head->ip_sum=checksum_calc;
              // const uint8_t* icmp_pkt=ip_pkt+sizeof(ip_hdr);
              SendICMPPkt(ip_head,iface,3,3);
              return;
      }

      ip_head->ip_ttl--;
      if(ip_head->ip_ttl==0){ //ttl到期，发送time exceed
          printf("ttl is 000000000000000000000\n");
          ip_head->ip_sum=checksum_calc;
          SendICMPPkt(ip_head, iface, 11, 0);
          return;
      }

      else{  //TTL没到期
          if(ip_head->ip_p==ip_protocol_icmp){ //ICMP
            printf("in icmp\n");
            const uint8_t* icmp_pkt=ip_pkt+sizeof(ip_hdr);
            icmp_hdr* icmp_header=(icmp_hdr*)icmp_pkt;
            if(icmp_header->icmp_type==8 && findIfaceByIp(ip_head->ip_dst)){ //echo了这个路由器
              printf("icmp typr 8 and equal\n");
                icmp_header->icmp_type=0; //echo reply
                icmp_header->icmp_code=0;
                icmp_header->icmp_sum=0;
                icmp_header->icmp_sum=cksum(icmp_header,sizeof(icmp_hdr));

                ip_head->ip_ttl=64;
                ip_head->ip_dst=ip_head->ip_src;
                ip_head->ip_src=iface->ip;
                ip_head->ip_sum=cksum((const void*)ip_head,20);
                Buffer return_buf=ArrayToBuffer((uint8_t*)(packet.data()),packet.size());
                SendPacketWithAutoARP(return_buf);
            }
              else{
                printf("in icmp esle\n");
                ip_head->ip_sum=cksum((const void*)ip_head,20);
                printf("in icmp cksum %d\n",ip_head->ip_sum);
                Buffer return_buf=ArrayToBuffer((uint8_t*)(packet.data()),packet.size());
                SendPacketWithAutoARP(return_buf);
              }
          }
          else{ //TCP UCP ...
            printf("here in tcp/udp!\n");
            ip_head->ip_sum=cksum((const void*)ip_head,20);
            Buffer return_buf=ArrayToBuffer((uint8_t*)(packet.data()),packet.size());
            SendPacketWithAutoARP(return_buf);
          }
        }
        break;
      }

    

    default:
      break;
  }

  printf("\n");
}



//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
