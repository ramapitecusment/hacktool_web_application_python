function csrfSafeMethod(method) {
  // these HTTP methods do not require CSRF protection
  return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}
$.ajaxSetup({
  beforeSend: function (xhr, settings) {
    if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
      xhr.setRequestHeader("X-CSRFToken", csrftoken);
    }
  }
});
// MAC ADDRESS
var MacChangeForm = $("#form_mac_change");
var MacInteface = $('#interface');
var MacNewMac = $('#new_mac');
var AlertMac = $('#mac_changer_result');
// NET SCAN
var NetScanForm = $('#form_network_scan');
var NetScanRange = $('#ip_net_scan');
var NetScanTextArea = $('#network_scan_textarea');
// ARP SPOOF
var ArpForm = $('#form_arp_spoofing');
var ArpTargerIP = $('#arp_target_ip');
var ArpGateWayIP = $('#arp_gateway_ip');
var ArpCancel = $('#cancelARPspoof');
var ArpResult = $('#arp_spoofing_result');
// PACKET SNIFFING
var PacSnifForm = $('#form_packet_sniffing');
var PacSnifInterface = $('#packet_sniffing_interface');
var PacSnifRes = $('#packet_sniffing_textarea');
var PacSnifLogin = $('#login_info_textarea');

var loc = window.location;
var wsStart = 'ws://';
if (loc.protocol == 'https:') {
  wsStart = 'wss://';
}

var endpoint = wsStart + loc.host + loc.pathname;
var socket = new WebSocket(endpoint);
console.log(endpoint);

socket.onmessage = function (e) {
  console.log("Message", e.data);
  var data = JSON.parse(e.data);
  if (data["message"]) {
    AlertMac.append("<div class='alert alert-success'>" + data["message"] + "</div>");
  }
  else if (data["error"]) {
    AlertMac.append("<div class='alert alert-danger'>" + data["error"] + "</div>");
  }
  else if(data["net_scan_result"]){
    NetScanTextArea.val(NetScanTextArea.val() + data["net_scan_result"] + '\n');//append(data["net_scan_result"] + '\n')
  }
  else if(data["net_scan_error"]){
    NetScanTextArea.val(NetScanTextArea.val() + data["net_scan_error"] + '\n');//append(data["net_scan_result"] + '\n')
  }
  else if(data["arp_spoof_result"]){
    $('.alert-success').remove();
    ArpResult.append("<div class='alert alert-success'>" + data["arp_spoof_result"] + "</div>");
  }
  else if(data["arp_spoof_error"]){
    ArpResult.append("<div class='alert alert-danger'>" + data["arp_spoof_error"] + "</div>");
  }
  else if(data["packet_sniffing_result"]){
    PacSnifRes.val(PacSnifRes.val() + data["packet_sniffing_result"] + '\n');//append(data["net_scan_result"] + '\n')
  }
  else if(data["packet_sniffing_login"]){
    PacSnifLogin.val(PacSnifLogin.val() + data["packet_sniffing_login"] + '\n');//append(data["net_scan_result"] + '\n')
    }
  else if(data["packet_sniffing_error"]){
    PacSnifRes.append("<div class='alert alert-danger'>" + data["packet_sniffing_error"] + "</div>");
  }
  else if(data["command_line_result"]){
    PacSnifRes.append("<div class='alert alert-danger'>" + data["command_line_result"] + "</div>");
  }
  else if(data["command_line_error"]){
    PacSnifRes.append("<div class='alert alert-danger'>" + data["command_line_error"] + "</div>");
  }
};

socket.onopen = function (e) {
  console.log("Open", e);
  //
  // Mac Change
  //
  MacChangeForm.submit(function (event) {
    event.preventDefault();
    $('.alert-success').remove();
    $('.alert-danger').remove();
    socket.send(JSON.stringify({
      interface: MacInteface.val(),
      new_mac: MacNewMac.val()
    }));
    MacChangeForm[0].reset();
  });
  //
  // MAC RESET
  //
  $(document).on('click','#resetMac', function(e){
    e.preventDefault();
    $('.alert-success').remove();
    $('.alert-danger').remove();
    socket.send(JSON.stringify({
      'reset_mac': 'reset_mac'
    }));
  });
  //
  // Net Scan
  //
  NetScanForm.submit(function (event){
    event.preventDefault();
    NetScanTextArea.val("");
    socket.send(JSON.stringify({
      range: NetScanRange.val(),
    }));
    NetScanForm[0].reset();
  });
  //
  // Arp Spoofing
  //
  ArpForm.submit(function (event){
    event.preventDefault();
    $('.alert-success').remove();
    $('.alert-danger').remove();
    socket.send(JSON.stringify({
      target_ip: ArpTargerIP.val(),
      gateway_ip: ArpGateWayIP.val(),
    }));
    ArpForm[0].reset();
  });
  //
  // CANCEL ARP SPOOF
  //
  $(document).on('click','#cancelARPspoof', function(e){
    e.preventDefault();
    socket.send(JSON.stringify({
      cancel_arp: 'cancel_arp',
      target_ip: ArpTargerIP.val(),
      gateway_ip: ArpGateWayIP.val(),
    }));
    ArpForm[0].reset();
  });
  //
  // Packet Sniffing
  //
  PacSnifForm.submit(function (event){
    event.preventDefault();
    PacSnifRes.val("");
    PacSnifLogin.val("");
    socket.send(JSON.stringify({
      interface: PacSnifInterface.val(),
    }));
    PacSnifForm[0].reset();
  });
};

socket.onerror = function (e) {
  console.log("Error", e);
};

socket.onclose = function (e) {
  console.log("Close", e);
};