from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from pox.lib.revent import Event,EventHalt,EventMixin

log = core.getLogger()

class ActiveGroupStateChanged(Event):
    def __str__ (self):
        return "Group with key: %s route should be recomputed",self.group_key
    
    def __init__ (self,group_key,group,streamer_state_builder):
        super(ActiveGroupStateChanged,self).__init__()
        self.group_key = group_key
        self.group_members = group["members"]
        self.group_streamer = group["streamer"]
        self.streamer_state_builder = streamer_state_builder
        
    def get_streamer_state_builder(self):
        return self.streamer_state_builder
    
    def get_group_data(self):
        return self.group_key,self.group_streamer,self.group_members
    
    
class ActiveGroupDeleted(Event):
    def __str__ (self):
        return "Group with key: %s deleted",self.group_key
    
    def __init__ (self,group_key,streamer_state_builder):
        super(ActiveGroupDeleted,self).__init__()
        self.group_key = group_key
        self.streamer_state_builder = streamer_state_builder
        
    def get_streamer_state_builder(self):
        return self.streamer_state_builder
    
    def get_group_key(self):
        return self.group_key
    
class IncompleteGroupStateChanged(Event):
    def __str__ (self):
        return "Group with key: %s incomplete, send block/unblock message",self.group_key
    
    def __init__ (self,group_key,groups,streamer_state_builder,flag):
        super(IncompleteGroupStateChanged,self).__init__()
        self.streamer = groups["streamer"]
        self.flag = flag
        self.group_key = group_key
        self.streamer_state_builder = streamer_state_builder
        
    def get_streamer_state_builder(self):
        return self.streamer_state_builder
    
    def get_group_data(self):
        return self.group_key,self.streamer,self.flag
    
    
class StreamerStateBuilder(EventMixin):
    _eventMixin_events = set([ActiveGroupStateChanged,ActiveGroupDeleted,IncompleteGroupStateChanged])
    _rule_priority_adjustment = -0x1000 
    ''' Groups are stored in this format 
        self.groups{(group_multicast_dstip,streamer_srcip):{streamer:'streamer.dpid',members:{dpid1:[ports],dpid2:[ports]}'''
    
    def __init__(self):
        self.groups = {}
        self.incomplete_groups = {}
        self.group_addrs = set()
        self.member_state_builder = None
        
        core.addListeners(self)
        core.listen_to_dependencies(self, ['MemberStateBuilder'])
        core.openflow.addListeners(self)

    def is_multicast(self, in_addr):
        if in_addr > IPAddr("224.0.0.0") and in_addr < IPAddr("239.255.255.255"):
            return True
        else:
            return False  
    
    def get_complete_groups(self):
        return self.groups
            
    def is_different(self,old_group,new_group):
        if len(old_group.keys()) != len(new_group.keys()):
            return True
        else:
            for dpid in new_group.keys():
                if dpid not in old_group.keys():
                    return True
                else:
                    if len(new_group[dpid]) != len(old_group[dpid]):
                        return True
                    else:
                        for port in new_group[dpid]:
                            if port not in old_group[dpid]:
                                return True
                         
        return False
    
    def raise_event_incomplete(self,grp_key,flag):
        ev = IncompleteGroupStateChanged(grp_key,self.incomplete_groups[grp_key],self,flag)
        self.raiseEvent(ev)
    
    def raise_event_modified(self,grp_key):
        ev = ActiveGroupStateChanged(grp_key,self.groups[grp_key],self)
        self.raiseEvent(ev)
        
    def raise_event_deleted(self,grp_key):
        ev = ActiveGroupDeleted(grp_key,self)
        self.raiseEvent(ev)
          
    def _handle_PacketIn(self,event):
        packet = event.parsed
        if packet.type == pkt.ethernet.IP_TYPE:
            ip_packet = packet.payload
                               
            if self.is_multicast(ip_packet.dstip) and ip_packet.protocol != ip_packet.IGMP_PROTOCOL:
                log.info("Multicast packet handled, IP: "+str(ip_packet.dstip))
                if ip_packet.dstip in self.group_addrs:
                    log.info("New streamer for group key: "+str(ip_packet.dstip)+":"+str(ip_packet.srcip))
                    group_key = (ip_packet.dstip,ip_packet.srcip)
                    passive_group = self.member_state_builder.get_valid_group_members(ip_packet.dstip,ip_packet.srcip)
                    log.info("Valid group data for this stream from other component: "+str(passive_group))
                    self.groups.update({group_key:{"members":passive_group, "streamer":event.dpid}})
                    log.info("Group after added streamer "+str(self.groups))
                    self.raise_event_modified(group_key)
                else:
                    log.info("Incomplete group block")
                    log.info("New streamer for group key: "+str(ip_packet.dstip)+":"+str(ip_packet.srcip))
                    group_key = (ip_packet.dstip,ip_packet.srcip)
                    self.incomplete_groups.update({group_key:{"members":{}, "streamer":event.dpid}})
                    log.info("Blocked Group after added streamer "+str(self.incomplete_groups))
                    self.raise_event_incomplete(group_key,"BLOCK")
                    
                return EventHalt 
   
    def _handle_MemberStateBuilder_PassiveGroupStateChanged(self,event):
        log.info("MemberStateBuilder handler invoked")
        if self.member_state_builder is None:
            self.member_state_builder = event.get_member_state_builder()
            
        log.info("Group addrs before: "+str(self.group_addrs))
        log.info("Groups before: "+str(self.groups))
        
        address = event.get_group_addr()
        self.group_addrs.add(address)
        
        for group_key in self.groups.keys():
            if group_key[0] == address:
                passive_group = self.member_state_builder.get_valid_group_members(group_key[0],group_key[1])
                log.info("Looping the existing groups, actual key: "+str(group_key))
                log.info("For this key the group members recieved from passive group builder: "+str(passive_group))
                is_different = self.is_different(self.groups[group_key]["members"],passive_group)
                if is_different:
                    self.groups[group_key]["members"] = passive_group
                    self.raise_event_modified(group_key)
        
        log.info("Incomplete groups before event handled: "+str(self.incomplete_groups))
        to_delete = []
        for group_key in self.incomplete_groups.keys():
            if address in group_key:
                passive_group = self.member_state_builder.get_valid_group_members(group_key[0],group_key[1])
                log.info("Looping the existing blocked groups, actual key which is updated: "+str(group_key))
                log.info("For this key the group members recieved from passive group builder: "+str(passive_group))
                to_delete.append(group_key)
                self.incomplete_groups[group_key]['members'] = passive_group
                self.groups.update({group_key:self.incomplete_groups[group_key]})
                self.raise_event_incomplete(group_key, 'UNBLOCK')
                self.raise_event_modified(group_key)
        
        for group_key in to_delete:
            self.incomplete_groups.pop(group_key)
        
        log.info("Incomplete groups after event handled: "+str(self.incomplete_groups))
                
        log.info("Group addrs after: "+str(self.group_addrs))
        log.info("Groups after: "+str(self.groups))
            
    def _handle_MemberStateBuilder_PassiveGroupDeleted(self,event):
        log.info("MemberStateBuilder handler invoked")
        if self.member_state_builder is None:
            self.member_state_builder = event.get_member_state_builder()
            
        log.info("Group addrs before: "+str(self.group_addrs))
        log.info("Groups before: "+str(self.groups))
        address = event.get_group_addr()
        
        self.group_addrs.remove(address)
        for group_key in self.groups.keys():
            if group_key[0] == address:
                self.groups.pop(group_key)
                self.raise_event_deleted(group_key)
        log.info("Group addrs after: "+str(self.group_addrs))
        log.info("Groups after: "+str(self.groups))
        
        
          
    
def launch():
    streamer_state_builder = StreamerStateBuilder()
    core.register("StreamerStateBuilder",streamer_state_builder)
