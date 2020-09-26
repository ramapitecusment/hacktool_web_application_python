// CODE INJECTOR
var Form = $("#code_injector_form");
var Port = $('#code_injector_port');
var Result = $('#code_injector_result');

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
  if (data["code_injector_result"]) {
    Result.append("<div class='alert alert-success'>" + data["code_injector_result"] + "</div>");
  }
  else if (data["code_injector_error"]) {
    Result.append("<div class='alert alert-danger'>" + data["code_injector_error"] + "</div>");
  }
};

socket.onopen = function (e) {
  console.log("Open", e);
  Form.submit(function (event) {
    event.preventDefault();
    $('.alert-success').remove();
    $('.alert-danger').remove();
    socket.send(JSON.stringify({
      code_injector_port: Port.val(),
    }));
    Form[0].reset();
  });
};

socket.onerror = function (e) {
  console.log("Error", e);
};

socket.onclose = function (e) {
  console.log("Close", e);
};