// SQL INJECTION SCAN
var Form = $("#form");
var TargetUrl = $('#target_url');
var Result = $('#result');
// AUTHENTIFICATION
var InputUsername = $('#inputUsername');
var Username = $('#username');
var InputPassword = $('#inputPassword');
var Password = $('#password');
var InputSubmit = $('#inputSubmit');
var SubmitType = $('#submitType');

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
  if (data["result"]) {
    Result.append("<div class='alert alert-success'>" + data["result"] + "</div>");
  }
  else if (data["error"]) {
    Result.append("<div class='alert alert-danger'>" + data["error"] + "</div>");
  }
};

socket.onopen = function (e) {
  console.log("Open", e);
  Form.submit(function (event) {
    event.preventDefault();
    $('.alert-success').remove();
    $('.alert-danger').remove();
    socket.send(JSON.stringify({
      targetUrl: TargetUrl.val(),
      inputUsername: InputUsername.val(),
      username: Username.val(),
      inputPassword: InputPassword.val(),
      password: Password.val(),
      inputSubmit: InputSubmit.val(),
      submitType: SubmitType.val(),
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