"use strict";
class Socket {
    constructor(url, options) {
        this.url = url
        this.options = options
        this.channels = {
            'open': () => { },
            'close': () => { },
        }
        this.user = ""
        this.listen()
    };

    listen() {
        try {
            this.socket = new WebSocket("wss://" + this.url);
            this.socket.trigger = this.trigger;

            this.socket.onopen = (msg) => {
                this.trigger('open', msg);
            };

            this.socket.onmessage = (event) => {
                var obj = JSON.parse(event.data);
                switch (obj.channel) {
                    case "connect":
                        this.user = obj.data;
                        break;
                    case "disconnect":
                        this.user = null;
                        break;
                    case "close":
                        this.user = null;
                        break;
                }
                this.trigger(obj.channel, obj.data, obj.sender);
            };
            this.socket.onclose = (event) => {
                this.trigger('close', event);
            };
        }
        catch (e) {
            console.warn(e);
        }


    };

    on(channel, handler) {
        this.channels[channel] = handler
    };

    trigger(channel, params, sender) {
        if (this.channels.hasOwnProperty(channel)) {
            this.channels[channel](params, sender);
        }
    };

    close() {
        if (this.socket != null) {
            this.socket.close();
            this.socket = null;
        }
    };

    reconnect() {
        this.close();
        this.listen();
    };

    commandwrapper(channel, data, broadcast) {
        let response = { 'channel': channel, 'data': data, 'sender': this.socket.user, 'broadcast': broadcast };
        response = JSON.stringify(response);
        return response;
    };

    emit(channel, data) {
        if (this.socket == null) { return; }
        let message = this.commandwrapper(channel, data, false);
        try {
            this.socket.send(message);
        } catch (e) {
            console.warn(e)
        }
    };

    push(channel, data, to) {
        if (this.socket == null) { return; }
        let message = this.commandwrapper(channel, { to: to, data: data }, false);

        try {
            this.socket.send(message);
        } catch (e) {
            console.warn(e);
        }

    };

    broadcast(channel, data) {
        if (this.socket == null) { return; }
        message = this.commandwrapper(channel, data, true);

        try {
            this.socket.send(message);
        } catch (e) {
            console.warn(e);
        }

    };
}
