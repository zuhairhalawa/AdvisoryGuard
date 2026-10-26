"use strict";
/* Preloaded with `node --require` to PROVE offline operation: any attempt to open a socket,
   resolve a name or call fetch aborts the process with a distinctive message. */
const net = require("node:net");
const dns = require("node:dns");

function blocked(what) {
  process.stderr.write("NETWORK-ATTEMPT-BLOCKED: " + what + "\n");
  process.exit(99);
}

net.Socket.prototype.connect = function () {
  blocked("net.Socket.connect");
};
for (const fn of ["lookup", "resolve", "resolve4", "resolve6"]) {
  dns[fn] = function () {
    blocked("dns." + fn);
  };
}
globalThis.fetch = function () {
  blocked("fetch");
};
