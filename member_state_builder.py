from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.revent import Event,EventHalt,EventMixin

log = core.getLogger()

MEMBERSHIP_REPORT_V2 = 0x16
LEAVE_GROUP_V2       = 0x17
MEMBERSHIP_REPORT_V3 = 0x22

MODE_IS_INCLUDE  = 1
MODE_IS_EXCLUDE  = 2
CHANGE_TO_INCLUDE_MODE = 3
CHANGE_TO_EXCLUDE_MODE = 4
ALLOW_NEW_SOURCES = 5
BLOCK_OLD_SOURCES = 6


class PassiveGroupStateChanged(Event):
    def __str__ (self):
        return "Passive group with IP: %s status changed",self.group_key
    
    def __init__ (self,address,member_state_builder):
        super(PassiveGroupStateChanged,self).__init__()
        self.address = address
        self.member_state_builder = member_state_builder
        
    def get_member_state_builder(self):
        return self.member_state_builder
    
    def get_group_addr(self):
        return self.address
    
class PassiveGroupDeleted(Event):
    def __str__ (self):
        return "Passive group with IP: %s deleted",self.group_key
    
    def __init__ (self,address,member_state_builder):
        super(PassiveGroupDeleted,self).__init__()
        self.address = address
        self.member_state_builder = member_state_builder
        
    def get_member_state_builder(self):
        return self.member_state_builder
    
    def get_group_addr(self):
        return self.address
    
class MemberStateBuilder(EventMixin):
    """The group data is stored in format:
       self.group_record = {"members":{}, "member_states":{(dpid,port):{"mode": "EXCLUDE/INCLUDE","source_set":set()}}}
       self.groups = {"ipaddress":self.group_record}
       """
    _eventMixin_events = set([PassiveGroupStateChanged,PassiveGroupDeleted])
    _rule_priority_adjustment = -0x1000 
    
    def __init__(self):
        self.groups = {}
        
        core.addListeners(self)
        core.openflow.addListeners(self)
        
    def _add_member_to_dict(self,dictionary,key,item):
        if key in dictionary:
            if item not in dictionary[key]:
                dictionary[key].append(item)
        else:
            dictionary.update({key:[item]})
        return dictionary
        
    def get_valid_group_members(self,address,source):
        group_rec = self.groups[address]
        group_members = {}
        
        for switch_data in group_rec["members"].iteritems():
            for port in switch_data[1]:
                dpid = switch_data[0]
                member_state = group_rec["member_states"][(dpid,port)]
                if member_state["mode"] == "INCLUDE":
                    if address in member_state["source_set"]:
                        group_members = self._add_member_to_dict(group_members, dpid, port)
                else:
                    if address not in member_state["source_set"]:
                        group_members = self._add_member_to_dict(group_members, dpid, port)

        return group_members            
                 
    def raise_event_modified(self,address):
        ev = PassiveGroupStateChanged(address,self)
        log.info("Raised a modified event")
        self.raiseEvent(ev)
        
    def raise_event_deleted(self,address):
        ev = PassiveGroupDeleted(address,self)
        log.info("Raised a deleted event")
        self.raiseEvent(ev)
        
    def update_group_member_states(self,event,address,mode,source_set):
        if len(source_set) == 0 and mode == "INCLUDE":
            log.info("To be deleted, before state of groups: "+str(self.groups))
            has_to_be_deleted = self.del_member(event, address)
            log.info("After the groups: "+str(self.groups))
            if has_to_be_deleted is True:
                self.raise_event_deleted(address)
            elif has_to_be_deleted is False:
                self.raise_event_modified(address)
            elif has_to_be_deleted is None:
                log.info("Bad packet,data to be deleted not found")
            return
        
        log.info("Update group status, groups before: "+str(self.groups))
        if self.groups.has_key(address):
            if self.groups[address]["members"].has_key(event.dpid):
                if event.port not in self.groups[address]["members"][event.dpid]:
                    self.groups[address]["members"][event.dpid].append(event.port)
                    member_state = {(event.dpid,event.port):{"mode": mode, "source_set":source_set}}
                    self.groups[address]["member_states"].update(member_state)
                                
            else:
                self.groups[address]["members"].update({event.dpid:[event.port]})
                member_state = {(event.dpid,event.port):{"mode": mode, "source_set":source_set}}
                self.groups[address]["member_states"].update(member_state)
                            
        else:
            group_rec = {"members":{event.dpid:[event.port]}, "member_states":{(event.dpid,event.port):{"mode": mode,"source_set":source_set}}}
            self.groups.update({address:group_rec})
            
        log.info("Update group status, groups after: "+str(self.groups))    
        self.raise_event_modified(address)

    def del_member(self,event,address):
        log.info("Delete invoked")
        if self.groups.has_key(address):
            if self.groups[address]["members"].has_key(event.dpid):
                if event.port in self.groups[address]["members"][event.dpid]:
                    port_index_to_del = self.groups[address]["members"][event.dpid].index(event.port)
                    del self.groups[address]["members"][event.dpid][port_index_to_del]
                                
                    self.groups[address]["member_states"].pop((event.dpid,event.port))
                                
                    if len(self.groups[address]["members"][event.dpid]) == 0:
                        self.groups[address]["members"].pop(event.dpid)
                        
                    if len(self.groups[address]["members"].keys()) == 0:
                        self.groups.pop(address)
                        return True
                    return False
        return None
                
                
    def _handle_PacketIn(self,event):
        packet = event.parsed
        
        if packet.type == pkt.ethernet.IP_TYPE:
            ip_packet = packet.payload
            if ip_packet.protocol == ip_packet.IGMP_PROTOCOL:
                igmp_packet = ip_packet.next
                log.info("Groups before packet handling: "+str(self.groups))
                if igmp_packet.ver_and_type == MEMBERSHIP_REPORT_V2:
                    self.update_group_member_states(event, igmp_packet.address, "EXCLUDE", set())
                        
                elif igmp_packet.ver_and_type == LEAVE_GROUP_V2:
                    self.update_group_member_states(event, igmp_packet.address, "INCLUDE", set())
                                
                elif igmp_packet.ver_and_type == MEMBERSHIP_REPORT_V3:
                    log.info("IGMPv3 packet")

                    for i in xrange(igmp_packet.grp_num):
                        actual_group_rec = igmp_packet.grp_rec[i]
                        log.info("Actual group rec addr: "+str(actual_group_rec.address))
                        log.info("Actaul group src set: "+str(actual_group_rec.src_addr))
                        log.info("Actual group rec type: "+str(actual_group_rec.type))
                        address = actual_group_rec.address
                        source_set =  set(actual_group_rec.src_addr)
                                              
                        if actual_group_rec.type == MODE_IS_INCLUDE:
                            log.info("Mode is include")
                            self.update_group_member_states(event, address, "INCLUDE",source_set)
                        
                        if actual_group_rec.type == MODE_IS_EXCLUDE:
                            log.info("Mode is exclude")
                            self.update_group_member_states(event, address, "EXCLUDE", source_set)
                        
                        if actual_group_rec.type == CHANGE_TO_INCLUDE_MODE:
                            log.info("Change to include")
                            self.update_group_member_states(event, address, "INCLUDE", source_set)
                        
                        if actual_group_rec.type == CHANGE_TO_EXCLUDE_MODE:
                            log.info("Change to exclude")
                            self.update_group_member_states(event, address, "EXCLUDE", source_set)
                        
                        if actual_group_rec.type == ALLOW_NEW_SOURCES:
                            log.info("Allow new sources")
                            try:
                                member_state = self.groups[address]["member_states"][(event.dpid,event.port)]
                            except KeyError:
                                member_state = {"mode": "INCLUDE", "source_set":set()}
                                   
                            if member_state["mode"] == "EXCLUDE":
                                source_set = member_state["source_set"].difference(source_set)
                                self.update_group_member_states(event, address, "EXCLUDE", source_set)
                            else:
                                source_set = member_state["source_set"].union(source_set)
                                self.update_group_member_states(event, address, "INCLUDE", source_set)
  
                        if actual_group_rec.type == BLOCK_OLD_SOURCES:
                            log.info("Block old sources")
                            try:
                                member_state = self.groups[address]["member_states"][(event.dpid,event.port)]
                            except KeyError:
                                member_state = {"mode": "INCLUDE", "source_set":set()}
                                
                            if member_state["mode"] == "EXCLUDE":
                                source_set = member_state["source_set"].union(source_set)
                                self.update_group_member_states(event, address, "EXCLUDE", source_set)
                            else:
                                source_set = member_state["source_set"].difference(source_set)
                                self.update_group_member_states(event, address, "INCLUDE", source_set)
                log.info("Groups after packet handling: "+str(self.groups))          
                return EventHalt
                                
def launch():
    member_state_builder = MemberStateBuilder()
    core.register("MemberStateBuilder",member_state_builder)