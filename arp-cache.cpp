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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{

  // FILL THIS IN
  for(auto& request: m_arpRequests){
    
    
    if(request->nTimesSent>=MAX_SENT_TIME){ //send host unreachable and remove
        printf("ip is invalid, send host unreachable\n");
        ip_hdr* ip_head=(ip_hdr*)((*(request->packets.begin())).packet.data()+sizeof(ethernet_hdr));
        const Interface* outface = m_router.findIfaceByName((*(request->packets.begin())).iface);

        m_router.SendICMPPkt(ip_head, outface, 3, 1);

        removeRequest(request);
    }
    else{
      auto now = steady_clock::now();
      if((now - request->timeSent)<seconds(1)) continue;

      const Interface* outface = m_router.findIfaceByName((*(request->packets.begin())).iface);
      ethernet_hdr arp_request_eth;
      u_int8_t flood_mac_addr[]={0xff,0xff,0xff,0xff,0xff,0xff};
      memcpy(arp_request_eth.ether_dhost,flood_mac_addr,6);
      memcpy(arp_request_eth.ether_shost,outface->addr.data(),6);
      arp_request_eth.ether_type=htons(ethertype_arp);
      arp_hdr arp_request_arp;
      arp_request_arp.arp_hrd=htons(arp_hrd_ethernet);
      arp_request_arp.arp_pro=htons(ethertype_ip);
      arp_request_arp.arp_hln=6;
      arp_request_arp.arp_pln=4;
      arp_request_arp.arp_op=htons(1);
      memcpy(arp_request_arp.arp_sha,outface->addr.data(),6);
      memcpy(arp_request_arp.arp_tha,flood_mac_addr,6);
      arp_request_arp.arp_sip=outface->ip;
      arp_request_arp.arp_tip=request->ip;
      Buffer arp_request=ArrayToBuffer((uint8_t*)&arp_request_eth,sizeof(arp_request_eth));
      AppendToEnd(arp_request,(uint8_t*)&arp_request_arp,sizeof(arp_request_arp));
      m_router.sendPacket(arp_request,(*(request->packets.begin())).iface);
      std::cout<<"///////////////////////"<<std::endl;
      print_hdrs(arp_request);
      std::cout<<"////////endl///////////"<<std::endl;

      request->timeSent = steady_clock::now();
      request->nTimesSent++;
    }
  }

  for(auto it = m_cacheEntries.begin(); it != m_cacheEntries.end(); ){
    if(!(*it)->isValid){
      it = m_cacheEntries.erase(it); // erase() 返回下一个有效的迭代器
    } else {
      ++it;
    }
  }
  
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip, bool lock=true)
{

  if(lock) std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface, bool lock=true)
{
  if(lock) std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
