from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each connected switch.
  A Connection object for that switch is passed into the __init__ function.
  """
  def __init__ (self, connection):
     # Keep track of the connection to the switch so we can send messages!
    self.connection = connection

      # Bind the PacketIn event listener
    connection.addListeners(self)

  def _handle_PacketIn (self, event):
    """
    Handle packet-in messages from the switch.
    """
    packet = event.parsed   # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message

     # Call the firewall function
    self.firewall(packet_in, packet)

  def send_packet (self, buffer_id, raw_data, out_port, in_port):
    """
     Send a packet to the specified port of the switch.
    If buffer_id is a valid buffer on the switch, use that buffer. Otherwise,
    send the raw_data in raw_data.
    "in_port" is the port number that the packet arrived on. Use OFPP_NONE if you created this packet.
    """
    msg = of.ofp_packet_out()
    msg.in_port = in_port
    if buffer_id != -1 and buffer_id is not None:
      msg.buffer_id = buffer_id
    else:
      if raw_data is None:
        return
      msg.data = raw_data

    action = of.ofp_action_output(port=out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)

  def firewall(self, packet_in, packet):
    # Allow ARP traffic
    if packet.find('arp'):
      # Flood the packet out all ports
      self.send_packet(packet_in.buffer_id, packet_in.data, of.OFPP_ALL, packet_in.in_port)
      
      # Install a flow rule to avoid processing future ARP packets
      msg = of.ofp_flow_mod()
      msg.match.dl_type = packet.type# Match ARP type
      #print({packet.type})
      msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
      self.connection.send(msg)
      log.debug("Allowing ARP traffic")

    # Allow ICMP traffic
    elif packet.find('icmp'):
      # Flood the packet out all ports
      self.send_packet(packet_in.buffer_id, packet_in.data, of.OFPP_ALL, packet_in.in_port)
      
      # Install a flow rule to avoid processing future ICMP packets
      msg = of.ofp_flow_mod()
      msg.match.nw_proto = 1 # ICMP
      msg.match.dl_type = packet.type 
      #print({packet.type})
      msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
      self.connection.send(msg)
      log.debug("Allowing ICMP traffic")

    # Drop any other traffic
    else:
      # Drop any other traffic
      msg = of.ofp_flow_mod()
      msg.match.dl_type = packet.type  # Match any other Ethernet type
      
      msg.actions = []  # Drop action
      self.connection.send(msg)
      log.debug("Dropping other traffic")

def launch ():
  """
   Starts the component when called.

  """
  def start_switch(event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)

    # Listen for switch connections and call start_switch
  core.openflow.addListenerByName("ConnectionUp", start_switch)
