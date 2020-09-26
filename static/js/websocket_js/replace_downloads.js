// REPLACE DOWNLOADS
var Form = $("#replace_downloads_form");
var Port = $('#replace_downloads_port');
var FileLocation = $('#replace_downloads_file_location');
var FileName = $('#replace_downloads_file_name');
var Result = $('#replace_downloads_result');

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
  if (data["replace_downloads_result"]) {
    Result.append("<div class='alert alert-success'>" + data["replace_downloads_result"] + "</div>");
  }
  else if (data["replace_downloads_error"]) {
    Result.append("<div class='alert alert-danger'>" + data["replace_downloads_error"] + "</div>");
  }
};

socket.onopen = function (e) {
  console.log("Open", e);
  Form.submit(function (event) {
    event.preventDefault();
    $('.alert-success').remove();
    $('.alert-danger').remove();
    socket.send(JSON.stringify({
      replace_downloads_port: Port.val(),
      replace_downloads_file_location: FileLocation.val(),
      replace_downloads_file_name: FileName.val(),
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