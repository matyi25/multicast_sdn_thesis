""" Graph class, contains the discovered network topology in nodes, edges format. Between the links there is an opportunity
  to compute with different distance values, therefore we have a dictionary to store these values (distances dict). We also store
  the ports which belong to exact links, in order to be able to insert the correct output ports on the selected route to the routers' flow table.
  
  The graph building is done by handling the openflow discovery component's LinkEvent events. The event can be of state up and down. Therefore we can delete or add a link. 
  When the structure is changed, the component raises a GraphStructureChanged event. After that, the handling component can query the graph structure. 
  """
from collections import defaultdict
from pox.core import core
from pox.lib.revent import EventHalt,Event,EventMixin

log = core.getLogger()

class GraphStructureChanged(Event):
    def __str__ (self):
        return "Graph Structure changed"
    
    def __init__ (self,graph_builder):
        super(GraphStructureChanged,self).__init__()
        self.graph_builder = graph_builder
        
    def get_graph_builder(self):
        return self.graph_builder
        
        
class GraphBuilder(EventMixin):
    _eventMixin_events = set([GraphStructureChanged])
    _rule_priority_adjustment = -0x1000 

    def __init__(self):
        core.addListeners(self)
        core.openflow_discovery.addListeners(self)
        
        self.nodes = []
        self.edges = defaultdict(list)
        self.distances = {}
        self.ports = {}
        
    def add_node(self, value):
        if value not in self.nodes:
            self.nodes.append(value)
            
    def del_node(self, value):
        if value in self.nodes:
            self.nodes.remove(value)
            
    def add_edge(self, from_node, from_port, to_node, to_port, distance):
        self.edges[from_node].append(to_node)
        self.distances[(from_node, to_node)] = distance
        self.ports[(from_node,to_node)] = (from_port,to_port)
    
    def del_edge(self,from_node, from_port, to_node, to_port):
        if from_node in self.edges.keys():
            to_delete_index = self.edges[from_node].index(to_node)
            del self.edges[from_node][to_delete_index]
            
            if len(self.edges[from_node]) == 0:
                self.edges.pop(from_node)
  
        if (from_node, to_node) in self.distances.keys():
            self.distances.pop((from_node, to_node))
        
        if (from_node,to_node) in self.ports.keys():
            self.ports.pop((from_node,to_node))
        
        was_there = False
        for item in self.edges.values():
            if to_node in item:
                was_there = True
                
        if was_there == False:
            self.del_node(to_node)
            
    def _handle_LinkEvent(self, event):
        if (event.added == True ):
            log.info("ConnectionUp, dpid1=%s , dpid2=%s" % (event.link.dpid1,event.link.dpid2))
            self.add_node(event.link.dpid1)
            self.add_node(event.link.dpid2)
            self.add_edge(event.link.dpid1, event.link.port1, event.link.dpid2, event.link.port2, 1)
        else:
            log.info("ConnectionDown, dpid1=%s, dpid2=%s" % (event.link.dpid1,event.link.dpid2))
            self.del_edge(event.link.dpid1, event.link.port1, event.link.dpid2, event.link.port2)
        
        ev = GraphStructureChanged(self)
        self.raiseEvent(ev)
        return EventHalt
        
    def get_nodes(self):
        return self.nodes
    
    def get_edges(self):
        return self.edges
    
    def get_distances(self):
        return self.distances
    
    def get_ports(self):
        return self.ports
    
    def minimal_cost_spanning_tree(self,received_group_members,root):
        valid_group_members = set()
        for member in received_group_members.keys():
            if member in self.nodes:
                valid_group_members.add(member)
            
        visited = set()
        visited_group_members = set()
        min_tree = []
        result_min_tree = []
        before_edges = {}
        
        nodes = set(self.nodes)
        group_members = set(valid_group_members)
        visited.add(root)
        if root in group_members:
            visited_group_members.add(root)
        
        """ The PRIM algorithm, runs while every group member is in the tree, but there can be plus edges, 
         not just the ones needed to be able to reach group members from streamer """
        
        unvisitable_nodes = set()
        while visited_group_members != group_members:
            not_visited = set()
            not_visited = nodes.difference(visited)
            
            min_edge = 0
            for visited_node in visited:
                for not_visited_node in not_visited:
                    temp_edge = (visited_node,not_visited_node)
                    if (temp_edge in self.distances.keys()):
                        if min_edge == 0:
                            min_edge = temp_edge
                        elif self.distances[temp_edge] < self.distances[min_edge]:
                            min_edge = (visited_node,not_visited_node)  
                            
            if min_edge == 0:
                log.info("Some group members are unreachable!!!")
                unvisitable_nodes = not_visited
                log.info("Unvisitable group members: "+str(unvisitable_nodes))
                break
            
            if not before_edges.has_key(min_edge[1]):
                before_edge = min_edge
                before_edges.update({min_edge[1]:before_edge})   
            
            if min_edge not in min_tree:
                min_tree.append(min_edge)
                
            visited.add(min_edge[1])
            if min_edge[1] in group_members:
                visited_group_members.add(min_edge[1])
                

        log.info("The before edge dict: "+str(before_edges))
        """ We find every group member, and with the help of the before_edges dict, which contains the before edge to every vertex
         in the computed min cost spanning tree. After this section only valid edges will be in the resul_min_tree. """
        
        group_members = group_members.difference(unvisitable_nodes) 
        log.info("Updated group member set: "+str(group_members))
        
        for member in group_members:
            if member == root:
                continue
            temp_edge = ()
            for edge in min_tree:
                if edge[1] == member:
                    temp_edge = edge
                    break
                
            result_min_tree.append(temp_edge)
            while temp_edge[0] != root:
                temp_edge = before_edges[temp_edge[0]]
                if temp_edge not in result_min_tree:
                    result_min_tree.append(temp_edge)
        
        return result_min_tree
    
    def construct_routes(self, result_min_tree,group_members):
        """ To be able to write out the exact routes to switches, we need the ports in each vertex, where we can find the group members.
         To achieve this, we return the constructed route  """
         
        constructed_route = {} 
        for edge in result_min_tree:
            from_node = edge[0]
            if constructed_route.has_key(from_node):
                constructed_route[from_node].append(self.ports[edge][0])
            else:
                constructed_route.update({from_node:[self.ports[edge][0]]})
                
            if group_members.has_key(from_node):
                constructed_route[from_node].append(group_members[from_node])
        
        for member in group_members.keys():
            if member not in constructed_route.keys() and member in self.nodes:
                constructed_route.update({member:group_members[member]})
               
        return constructed_route

def launch():
    graph_builder = GraphBuilder()
    core.register("GraphBuilder",graph_builder)
    