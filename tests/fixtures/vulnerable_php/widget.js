function render(data) {
  document.getElementById('out').innerHTML = data.html;   // RULE-SRC-010
  document.write(location.hash);                          // RULE-SRC-011
  var fn = eval(data.code);                               // RULE-SRC-012
  document.getElementById('safe').innerHTML = "static";   // safe
}
