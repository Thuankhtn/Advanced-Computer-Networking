# Part 3 of UWCSE's Project 3
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from pox.lib.packet.arp import arp

log = core.getLogger()


#statically allocate a routing table for hosts
#MACs used only in part 4
IPS = {
  "h10" : ("10.0.1.10", '00:00:00:00:00:01', 1),
  "h20" : ("10.0.2.20", '00:00:00:00:00:02', 2),
  "h30" : ("10.0.3.30", '00:00:00:00:00:03', 3),
  "hnotrust1" : ("172.16.10.100", '00:00:00:00:00:05', 4),
  "serv1" : ("10.0.4.10", '00:00:00:00:00:04', 5),
}


class Part3Controller (object):
  
  def __init__ (self, connection):
    print (connection.dpid)
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)
    #use the dpid to figure out what switch is being created
    if (connection.dpid == 1):
      self.s1_setup()
    elif (connection.dpid == 2):
      self.s2_setup()
    elif (connection.dpid == 3):
      self.s3_setup()
    elif (connection.dpid == 21):
      self.cores21_setup()
    elif (connection.dpid == 31):
      self.dcs31_setup()
    else:
      print ("UNKNOWN SWITCH")
      exit(1)

  def s1_setup(self):
    self.allow_all()
    self.drop()   
  def s2_setup(self):
    self.allow_all()
    self.drop()
  def s3_setup(self):
    self.allow_all()
    self.drop()
  
  def cores21_setup(self):
    # drop ICMP packets from hnotrust
    msg = of.ofp_flow_mod()
    msg.priority = 100
    msg.match.dl_type = 0x0800
    msg.match.nw_proto = 1
    msg.match.nw_src = IPAddr('172.16.10.100')
    self.connection.send(msg)
		
    
    # block all ICMP traffic from untrusted host
    msg_ipv4_block = of.ofp_flow_mod()
    msg_ipv4_block.priority = 90 #
    msg_ipv4_block.match.dl_type = 0x0800 # IPv4
    msg_ipv4_block.match.nw_src = IPAddr('172.16.10.100') # from untrusted host
    msg_ipv4_block.match.nw_dst = IPAddr('10.0.4.10') # to datacenter
    # no actions added
    self.connection.send(msg_ipv4_block)

    # actual routing
    # h10
    msg_1 = of.ofp_flow_mod()
    msg_1.priority = 80
    msg_1.match.dl_type = 0x0800 # IPv4
    msg_1.match.nw_dst = IPAddr('10.0.1.10')
    msg_1.actions.append(of.ofp_action_output(port = 1)) 
    self.connection.send(msg_1)

    # h20
    msg_2 = of.ofp_flow_mod()
    msg_2 .priority = 80
    msg_2 .match.dl_type = 0x0800 # IPv4
    msg_2 .match.nw_dst = IPAddr('10.0.2.20')# to host 2
    msg_2 .actions.append(of.ofp_action_output(port = 2)) 
    self.connection.send(msg_2 )

    # h30
    msg_3 = of.ofp_flow_mod()
    msg_3.priority = 80
    msg_3.match.dl_type = 0x0800 # IPv4
    msg_3.match.nw_dst = IPAddr('10.0.3.30') # to host 3
    msg_3.actions.append(of.ofp_action_output(port = 3))
    self.connection.send(msg_3)

    #Allow IPv4 to serv1
    msg_serv1 = of.ofp_flow_mod()
    msg_serv1.priority = 80
    msg_serv1.match.dl_type = 0x0800 # IPvdc
    msg_serv1.match.nw_dst = IPAddr('10.0.4.10') # to host dc
    msg_serv1.actions.append(of.ofp_action_output(port = 4)) 
    self.connection.send(msg_serv1)

    # out to the Internet
    msg_all = of.ofp_flow_mod()
    msg_all.priority = 80
    msg_all.match.dl_type = 0x0800 # IPv4
    msg_all.actions.append(of.ofp_action_output(port = 5)) 
    self.connection.send(msg_all)
   
    self.allow_all()
    # show never reach here
    self.drop()


  def dcs31_setup(self):

    self.allow_all()
    self.drop()

  def allow_all(self):
    msg = of.ofp_flow_mod()
    msg.priority = 1 # a slightly higher priority than drop
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    self.connection.send(msg)
  def drop(self):
    # drop other packets
    msg_drop = of.ofp_flow_mod()
    # ICMP
    msg_drop.priority = 0 # a low priority
    # flood all ports
    self.connection.send(msg_drop)

  #used in part 4 to handle individual ARP packets
  #not needed for part 3 (USE RULES!)
  #causes the switch to output packet_in on out_port

  def resend_packet(self, packet_in, out_port):
    msg = of.ofp_packet_out()
    msg.data = packet_in
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)
    self.connection.send(msg)

  def _handle_PacketIn (self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    print ("Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump())


def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Part3Controller(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
