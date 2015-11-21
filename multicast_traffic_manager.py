from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from pox.lib.revent import EventHalt

log = core.getLogger()

class MulticastTrafficManager():
    def __init__(self):
        core.listen_to_dependencies(self, ['GraphBuilder','StreamerStateBuilder'])
        self.streamer_state_builder = None
        self.graph_builder = None
        self.flow_entries = {}
    
    def _handle_GraphBuilder_GraphStructureChanged(self, event):
        if self.graph_builder == None:
            self.graph_builder = event.get_graph_builder()
        
        log.info("Compute path invoked")
        
        nodes = self.graph_builder.get_nodes()
        edges = self.graph_builder.get_edges()
        distances = self.graph_builder.get_distances()
        ports = self.graph_builder.get_ports()
        
        log.info("Nodes: " + str(nodes))
        log.info("Edges: " + str(edges))
        log.info("Distances: " + str(distances))
        log.info("Ports: " + str(ports))
        
        # Recompute and write out these groups
        if self.streamer_state_builder is not None:
            active_groups = self.streamer_state_builder.get_complete_groups()
            log.info("Flow entries before: "+str(self.flow_entries))
            
            for group_key in active_groups.keys():        
                constructed_route = self.construct_routes(active_groups[group_key]["members"], active_groups[group_key]["streamer"])
                
                if self.flow_entries.has_key(group_key):
                    self.remove_old_route(self.flow_entries[group_key], group_key)
                
                if len(constructed_route) != 0:
                    self.write_route(constructed_route,group_key)
            
                self.validate_flow_entries(constructed_route,group_key)
                
            log.info("Flow entries after: "+str(self.flow_entries))
        return EventHalt
    
    def  _handle_StreamerStateBuilder_ActiveGroupStateChanged(self, event):
        group_key,streamer,members = event.get_group_data()
        
        log.info("Key:"+str(group_key))
        log.info("Streamer:"+str(streamer))
        log.info("Members:"+str(members))
        
        if self.streamer_state_builder == None:
            self.streamer_state_builder = event.get_streamer_state_builder()
            
        constructed_route = self.construct_routes(members,streamer)
        log.info("Constructed path: "+str(constructed_route))
        
        if self.flow_entries.has_key(group_key):
            self.remove_old_route(self.flow_entries[group_key], group_key)
        
        if len(constructed_route) != 0:
            self.write_route(constructed_route,group_key)
        
        self.validate_flow_entries(constructed_route,group_key)
        
        log.info("Flow entries: "+str(self.flow_entries))
        
    def  _handle_StreamerStateBuilder_ActiveGroupDeleted(self, event):
        log.info("Group deleted event handler in multicast")
        log.info("FLow entries before: "+str(self.flow_entries))
        if self.streamer_state_builder == None:
            self.streamer_state_builder = event.get_streamer_state_builder()
            
        group_key = event.get_group_key()
        if self.flow_entries.has_key(group_key):
            self.remove_old_route(self.flow_entries[group_key], group_key)
            self.flow_entries.pop(group_key)
            
        log.info("FLow entries after: "+str(self.flow_entries))
    
    
    def  _handle_StreamerStateBuilder_IncompleteGroupStateChanged(self, event):
        log.info("Group incomplete block/unblock event handler in multicast")
            
        group_key,streamer,flag = event.get_group_data()
        self.send_incomplete_group_message(group_key, streamer, flag)
       
        
    def construct_routes(self, group_members, group_streamer):
        min_cost_tree = self.graph_builder.minimal_cost_spanning_tree(group_members, group_streamer)
        constructed_routes = self.graph_builder.construct_routes(min_cost_tree,group_members)
        
        log.info("Min cost tree: "+str(min_cost_tree))
        
        return constructed_routes
    
    def validate_flow_entries(self, constructed_route, group_key):
        if len(constructed_route) != 0:
            if self.flow_entries.has_key(group_key):
                self.flow_entries[group_key] = constructed_route
            else:
                self.flow_entries.update({group_key:constructed_route})
        else:
            if self.flow_entries.has_key(group_key):
                self.flow_entries.pop(group_key)
            
    def remove_old_route(self, old_route, group_key):
        for node in old_route.keys():
                msg = of.ofp_flow_mod()
                msg.priority = 65535
                msg.command = of.OFPFC_DELETE
                msg.match.dl_type = 0x800
                msg.match.nw_dst = IPAddr(group_key[0])
                msg.match.nw_src = IPAddr(group_key[1])
                try:
                    core.openflow.getConnection(node).send(msg)
                except AttributeError:
                    log.info("Core is going down, can't post update for this node")
        
    def write_route(self, constructed_route, group_key):
        for node in constructed_route.keys():
            msg = of.ofp_flow_mod()
            msg.priority = 65535
            msg.match.dl_type = 0x800
            msg.match.nw_dst = IPAddr(group_key[0])
            msg.match.nw_src = IPAddr(group_key[1])
            for out_port in constructed_route[node]:
                msg.actions.append(of.ofp_action_output(port = out_port))
            try:
                core.openflow.getConnection(node).send(msg)
            except AttributeError:
                log.info("Core is going down, can't post update for this node")    
                
    def send_incomplete_group_message(self,group_key,streamer,flag):
        msg = of.ofp_flow_mod()
        msg.priority = 65535
        msg.match.dl_type = 0x800
        if flag == 'UNBLOCK':
            msg.command = of.OFPFC_DELETE
        msg.match.nw_dst = IPAddr(group_key[0])
        msg.match.nw_src = IPAddr(group_key[1])
        msg.actions = []
        try:
            log.info("Incomplete group message sent out with flag "+str(flag))
            core.openflow.getConnection(streamer).send(msg)
        except AttributeError:
            log.info("Core is going down, can't post update for this node")

def launch():
    multicast_traffic_manager = MulticastTrafficManager()
    core.register("MulticastTrafficManager", multicast_traffic_manager)
