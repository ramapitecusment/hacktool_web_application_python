// DNS SPOOFING
var DNSSpoofForm = $("#form_dns_spoofing");
var DNSSpoofWEB = $('#dns_spoofing_website');
var DNSSpoofIP = $('#dns_spoofing_server_ip');
var DNSSpoofRES = $('#dns_spoofing_result');

var loc = window.location;
var wsStart = 'ws://';``
if (loc.protocol == 'https:') {
  wsStart = 'wss://';
}
var endpoint = wsStart + loc.host + loc.pathname;
var socket = new WebSocket(endpoint);
console.log(endpoint);

socket.onmessage = function (e) {
  console.log("Message", e.data);
  var data = JSON.parse(e.data);
  if (data["dns_spoofing_result"]) {
    DNSSpoofRES.append("<div class='alert alert-success'>" + data["dns_spoofing_result"] + "</div>");
  }
  else if (data["dns_spoofing_error"]) {
    DNSSpoofRES.append("<div class='alert alert-danger'>" + data["dns_spoofing_error"] + "</div>");
  }
};

socket.onopen = function (e) {
  console.log("Open", e);
  //
  // DNS SPOOFING
  //
  DNSSpoofForm.submit(function (event) {
    event.preventDefault();
    $('.alert-success').remove();
    $('.alert-danger').remove();
    socket.send(JSON.stringify({
      dns_spoof_website: DNSSpoofWEB.val(),
      dns_spoof_serverIP: DNSSpoofIP.val()
    }));
    DNSSpoofForm[0].reset();
  });
};

socket.onerror = function (e) {
  console.log("Error", e);
};

socket.onclose = function (e) {
  
  console.log("Close", e);
  socket.close()
};