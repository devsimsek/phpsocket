<?php
class LightSocket extends WebSocketServer
{

  /**
   *  commands
   *
   *  An object holding all available commands
   *
   *  @access public
   *
   *  @var  object
   *
   */
  public $commands;


  /**
   *  numUsers
   *
   *  An integer holding number of users
   *
   *  @access public
   *
   *  @var  int
   *
   */
  public $numUsers = 0;


  /**
   *  socketID
   *
   *  An array holding all available socket IDs
   *
   *  @access public
   *
   *  @var  array
   *
   */
  public $socketID = array();

  public $user;


  /**
   *  usernames
   *
   *  An object holding all available users
   *
   *  @access public
   *
   *  @var  object
   *
   */
  public $usernames = array();

  /**
   *  on
   *
   *  This is used to package a request to the socket server
   *
   *  @param  string  $channel     The command to be broadcasted e.g. chat
   *  @param  object  $cb      The function callback attached to the command
   */
  public function on($channel, $cb)
  {
    $this->commands["$channel"] = $cb;
  }


  /**
   *  process
   *
   *  This is called immediately when the data is recieved. and is used internally to send messages to clients.
   *
   *  @param  object  $user     The user object of the client sending the message
   *  @param  object  $message  The message object to be sent
   *
   *  @access protected
   */
  protected function process($user, $message)
  {
    $this->user = $user;

    $message = json_decode($message);

    if (!isset($message) && is_null($message)) {
      $message = new \stdClass();
      $message->channel = "";
      $message->data = "";
      $message->sender = "";
    }

    $message->sender = isset($message->sender) ? $message->sender : 0;

    if (isset($message->broadcast) && $message->broadcast) {
      //broadcast message
      $message->broadcast = false;
      $data = json_encode($message);

      foreach ($this->users as $user) {
        $this->send($user, $data);
      }

    } else {
      //non-broadcast message
      $this->trigger($message->channel, $message->data, $message->sender);
    }
  }

  /**
   * getUserById
   *
   * Fetches a user object via its id
   *
   */
  public function getUserById($userid)
  {
    foreach ($this->users as $user) {
      if ($user->id == $userid) {
        return $user;
      }
    }
    return null;
  }

  /**
   * getUserByName
   *
   * Fetches a user object by the Name
   *
   */
  public function getUserByName($username)
  {
    foreach ($this->socketID as $uid => $uname) {
      if ($uname == $username) {
        return $this->getUserById($uid);
      }
    }
    return null;
  }


  /**
   *  trigger
   *
   * This will trigger a command that has already been using using the on function
   *
   *  @param  string  $channel     The command to be broadcasted e.g. chat
   *  @param  string  $data    (Optional) The data to be broadcasted along with the command e.g. hello world
   *  @param  string  $sender   (Optional) the id of the user that is sending the message
   */
  public function trigger($channel, $params = '', $sender = null)
  {
    if (!isset($this->commands["$channel"])) {
      return;
    }
    $this->commands["$channel"]($this, $params, $sender);
  }

  /**
   *  connected
   *
   *  This is executed when socket connection is established for a particular user
   *  A welcome message is also send back to the client
   *
   *  @param  object  $user     The user object of the client sending the message
   *
   *  @access protected
   *
   */
  protected function connected($user)
  {
    $this->user = $user;
    $this->trigger("connect", $user->id);
  }

  /**
   *  disconnect
   *
   *   This is executed when a client is disconnected. It is a cleanup function.
   *
   *   @param  object   $socket    			The socket object of the connected client
   *   @param  boolean  $triggerClosed   		Flag to determine if close was triggered by client
   *   @param  boolean  $sockErrNo   			(optional) Socket error number
   *
   *   @access protected
   */
  protected function disconnect($socket, $triggerClosed = true, $sockErrNo = null)
  {
    if (isset($this->user))
      $this->trigger("disconnect", $this->user->id);
    parent::disconnect($socket, $triggerClosed, $sockErrNo);
  }

  /**
   *  closed
   *
   *   This is where cleanup would go, in case the user had any sort of
   *   open files or other objects associated with them.  This runs after the socket
   *   has been closed, so there is no need to clean up the socket itself here.
   *
   *   @param  object  $user    The user object of the connected client
   *
   *   @access protected
   */
  protected function closed($user)
  {
  }

  /**
   *  emit
   *
   * send message to current user only
   *
   *  @param  string  $channel     The command to be broadcasted e.g. chat
   *  @param  string  $data    (Optional) The data to be broadcasted along with the command e.g. hello world
   */
  public function emit($channel, $data)
  {
    $this->send($this->user, $this->cmdwrap($channel, $data));
  }

  /**
   *   push
   *
   *   send message to specified user only
   *
   *   @param  object  $user    The user object of the recipient (or the user id)
   *   @param  string  $channel     The command to be broadcasted e.g. chat
   *   @param  string  $data    (Optional) The data to be broadcasted along with the command e.g. hello world
   */
  public function push($user, $channel, $data)
  {
    $this->send($user, $this->cmdwrap($channel, $data));
  }

  /**
   *  cmdwrap
   *
   * This is used internally to package the entire information of command, data and sender into a json object
   *
   *  @param  string  $channel     The command to be broadcasted e.g. chat
   *  @param  string  $data    (Optional) The data to be broadcasted along with the command e.g. hello world
   */
  private function cmdwrap($channel, $data)
  {
    if (isset($this->user)) {
      $response = array('channel' => $channel, 'data' => $data, 'sender' => $this->user->id);
      return json_encode($response);
    }
    return "{'status':'unauthorized'}";
  }


  /**
   *  broadcast
   *
   * This is used to send a message to all connected users
   *
   *  @param  string  $channel     The command to be broadcasted e.g. chat
   *  @param  string  $data    (Optional) The data to be broadcasted along with the command e.g. hello world
   *  @param  boolean  $self   (Optional) true means the message should also be broadcasted to the sender
   */
  public function broadcast($channel, $data = '', $self = false)
  {
    $data = $this->cmdwrap($channel, $data);

    foreach ($this->users as $user) {
      if (!$self && $user == $this->user) {
        continue;
      }
      $this->send($user, $data);
    }
  }

  /**
   * get_all_users
   *
   * Returns an array of all available user IDs
   */
  public function get_all_users()
  {
    $users = array();
    foreach ($this->users as $user) {
      $users[] = $user->id;
    }
    return $users;
  }

  /**
   * listen
   *
   * This will initiate the websocket server and start waiting for client connections
   */
  public function listen()
  {
    try {
      $this->run();
    } catch (Exception $e) {
      $this->stdout($e->getMessage());
    }
  }
}


class WebSocketUser
{
  public $socket;
  public $id;
  public $name;
  public $headers = array();
  public $handshake = false;

  public $handlingPartialPacket = false;
  public $partialBuffer = "";

  public $sendingContinuous = false;
  public $partialMessage = "";

  public $hasSentClose = false;

  public $requestedResource;

  function __construct($id, $socket)
  {
    $this->id = $id;
    $this->socket = $socket;
  }
}

abstract class WebSocketServer
{
  protected $userClass = 'WebSocketUser';
  protected $maxBufferSize;
  protected $master;
  protected $sockets = array();
  protected $users = array();
  protected $heldMessages = array();
  protected $interactive = true;
  protected $headerOriginRequired = false;
  protected $headerSecWebSocketProtocolRequired = false;
  protected $headerSecWebSocketExtensionsRequired = false;

  public function __construct($addr, $port, $bufferLength = 2048)
  {
    $this->maxBufferSize = $bufferLength;
    $this->master = socket_create(AF_INET, SOCK_STREAM, SOL_TCP) or die("Failed: socket_create()");
    socket_set_option($this->master, SOL_SOCKET, SO_REUSEADDR, 1) or die("Failed: socket_option()");
    socket_bind($this->master, $addr, $port) or die("Failed: socket_bind()");
    socket_listen($this->master, 20) or die("Failed: socket_listen()");
    $this->sockets['m'] = $this->master;

    $host = gethostname();
    $ip = gethostbyname($host);
    $this->stdout("Server started\nListening on: $addr:$port\nServer's ip: $ip\nServer's host: $host");

  }
  abstract protected function process($user, $message); // Called immediately when the data is recieved.
  abstract protected function connected($user); // Called after the handshake response is sent to the client.
  abstract protected function closed($user); // Called after the connection is closed.
  protected function connecting($user)
  {
    // Override to handle a connecting user, after the instance of the User is created, but before
    // the handshake has completed.
  }

  protected function send($user, $message)
  {
    if ($user->handshake) {
      $message = $this->frame($message, $user);
      @socket_write($user->socket, $message, strlen($message));
    } else {
      // User has not yet performed their handshake.  Store for sending later.
      $holdingMessage = array('user' => $user, 'message' => $message);
      $this->heldMessages[] = $holdingMessage;
    }
  }
  protected function tick()
  {
    // Override this for any process that should happen periodically.  Will happen at least once
    // per second, but possibly more often.
  }
  protected function _tick()
  {
    // Core maintenance processes, such as retrying failed messages.
    foreach ($this->heldMessages as $key => $hm) {
      $found = false;
      foreach ($this->users as $currentUser) {
        if ($hm['user']->socket == $currentUser->socket) {
          $found = true;
          if ($currentUser->handshake) {
            unset($this->heldMessages[$key]);
            $this->send($currentUser, $hm['message']);
          }
        }
      }
      if (!$found) {
        // If they're no longer in the list of connected users, drop the message.
        unset($this->heldMessages[$key]);
      }
    }
  }
  /**
   * Main processing loop
   */
  public function run()
  {
    while (true) {
      if (empty($this->sockets)) {
        $this->sockets['m'] = $this->master;
      }
      $read = $this->sockets;
      $write = $except = null;
      $this->_tick();
      $this->tick();
      @socket_select($read, $write, $except, 1);
      foreach ($read as $socket) {
        if ($socket == $this->master) {
          $client = socket_accept($socket);
          if ($client < 0) {
            $this->stderr("Failed: socket_accept()");
            continue;
          } else {
            $this->connect($client);
            // $this->stdout("Client connected. "); // $client
          }
        } else {
          $numBytes = @socket_recv($socket, $buffer, $this->maxBufferSize, 0);
          if ($numBytes === false) {
            $sockErrNo = socket_last_error($socket);
            switch ($sockErrNo) {
              case 102: // ENETRESET    -- Network dropped connection because of reset
              case 103: // ECONNABORTED -- Software caused connection abort
              case 104: // ECONNRESET   -- Connection reset by peer
              case 108: // ESHUTDOWN    -- Cannot send after transport endpoint shutdown -- probably more of an error on our part, if we're trying to write after the socket is closed.  Probably not a critical error, though.
              case 110: // ETIMEDOUT    -- Connection timed out
              case 111: // ECONNREFUSED -- Connection refused -- We shouldn't see this one, since we're listening... Still not a critical error.
              case 112: // EHOSTDOWN    -- Host is down -- Again, we shouldn't see this, and again, not critical because it's just one connection and we still want to listen to/for others.
              case 113: // EHOSTUNREACH -- No route to host
              case 121: // EREMOTEIO    -- Rempte I/O error -- Their hard drive just blew up.
              case 125: // ECANCELED    -- Operation canceled

                $this->stderr("Unusual disconnect on socket " . $socket);
                $this->disconnect($socket, true, $sockErrNo); // disconnect before clearing error, in case someone with their own implementation wants to check for error conditions on the socket.
                break;
              default:
                $this->stderr('Socket error: ' . socket_strerror($sockErrNo));
            }

          } elseif ($numBytes == 0) {
            $this->disconnect($socket);
            print_r($socket);
            $this->stderr("Client disconnected. TCP connection lost"); // socket
          } else {
            $user = $this->getUserBySocket($socket);
            if (!$user->handshake) {
              $tmp = str_replace("\r", '', $buffer);
              if (strpos($tmp, "\n\n") === false) {
                continue; // If the client has not finished sending the header, then wait before sending our upgrade response.
              }
              $this->doHandshake($user, $buffer);
            } else {
              //split packet into frame and send it to deframe
              $this->split_packet($numBytes, $buffer, $user);
            }
          }
        }
      }
    }
  }
  protected function connect($socket)
  {
    $user = new WebSocketUser(uniqid('u'), $socket);
    $this->users[$user->id] = $user;
    $this->sockets[$user->id] = $socket;
    $this->connecting($user);
    $this->stdout("Client connected. id: " . $user->id);
  }
  protected function disconnect($socket, $triggerClosed = true, $sockErrNo = null)
  {
    $disconnectedUser = $this->getUserBySocket($socket);

    if ($disconnectedUser !== null) {
      unset($this->users[$disconnectedUser->id]);

      if (array_key_exists($disconnectedUser->id, $this->sockets)) {
        unset($this->sockets[$disconnectedUser->id]);
      }

      if (!is_null($sockErrNo)) {
        socket_clear_error($socket);
      }
      if ($triggerClosed) {
        $this->stdout("Client disconnected. id: " . $disconnectedUser->id); // $disconnectedUser->socket
        $this->closed($disconnectedUser);
        socket_close($disconnectedUser->socket);
      } else {
        $message = $this->frame('', $disconnectedUser, 'close');
        @socket_write($disconnectedUser->socket, $message, strlen($message));
      }
    }
  }
  protected function doHandshake($user, $buffer)
  {
    $magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    $headers = array();
    $lines = explode("\n", $buffer);
    foreach ($lines as $line) {
      if (strpos($line, ":") !== false) {
        $header = explode(":", $line, 2);
        $headers[strtolower(trim($header[0]))] = trim($header[1]);
      } elseif (stripos($line, "get ") !== false) {
        preg_match("/GET (.*) HTTP/i", $buffer, $reqResource);
        $headers['get'] = trim($reqResource[1]);
      }
    }
    if (isset($headers['get'])) {
      $user->requestedResource = $headers['get'];
    } else {
      // todo: fail the connection
      $handshakeResponse = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
    }
    if (!isset($headers['host']) || !$this->checkHost($headers['host'])) {
      $handshakeResponse = "HTTP/1.1 400 Bad Request";
    }
    if (!isset($headers['upgrade']) || strtolower($headers['upgrade']) != 'websocket') {
      $handshakeResponse = "HTTP/1.1 400 Bad Request";
    }
    if (!isset($headers['connection']) || strpos(strtolower($headers['connection']), 'upgrade') === FALSE) {
      $handshakeResponse = "HTTP/1.1 400 Bad Request";
    }
    if (!isset($headers['sec-websocket-key'])) {
      $handshakeResponse = "HTTP/1.1 400 Bad Request";
    }
    if (!isset($headers['sec-websocket-version']) || strtolower($headers['sec-websocket-version']) != 13) {
      $handshakeResponse = "HTTP/1.1 426 Upgrade Required\r\nSec-WebSocketVersion: 13";
    }
    if (($this->headerOriginRequired && !isset($headers['origin'])) || ($this->headerOriginRequired && !$this->checkOrigin($headers['origin']))) {
      $handshakeResponse = "HTTP/1.1 403 Forbidden";
    }
    if (($this->headerSecWebSocketProtocolRequired && !isset($headers['sec-websocket-protocol'])) || ($this->headerSecWebSocketProtocolRequired && !$this->checkWebsocProtocol($headers['sec-websocket-protocol']))) {
      $handshakeResponse = "HTTP/1.1 400 Bad Request";
    }
    if (($this->headerSecWebSocketExtensionsRequired && !isset($headers['sec-websocket-extensions'])) || ($this->headerSecWebSocketExtensionsRequired && !$this->checkWebsocExtensions($headers['sec-websocket-extensions']))) {
      $handshakeResponse = "HTTP/1.1 400 Bad Request";
    }
    // Done verifying the _required_ headers and optionally required headers.
    if (isset($handshakeResponse)) {
      socket_write($user->socket, $handshakeResponse, strlen($handshakeResponse));
      $this->disconnect($user->socket);
      return;
    }
    $user->headers = $headers;
    $user->handshake = $buffer;
    $webSocketKeyHash = sha1($headers['sec-websocket-key'] . $magicGUID);
    $rawToken = "";
    for ($i = 0; $i < 20; $i++) {
      $rawToken .= chr(hexdec(substr($webSocketKeyHash, $i * 2, 2)));
    }
    $handshakeToken = base64_encode($rawToken) . "\r\n";
    $subProtocol = (isset($headers['sec-websocket-protocol'])) ? $this->processProtocol($headers['sec-websocket-protocol']) : "";
    $extensions = (isset($headers['sec-websocket-extensions'])) ? $this->processExtensions($headers['sec-websocket-extensions']) : "";
    $handshakeResponse = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: $handshakeToken$subProtocol$extensions\r\n";
    socket_write($user->socket, $handshakeResponse, strlen($handshakeResponse));
    $this->connected($user);
  }
  protected function checkHost($hostName)
  {
    return true; // Override and return false if the host is not one that you would expect.
    // Ex: You only want to accept hosts from the my-domain.com domain,
    // but you receive a host from malicious-site.com instead.
  }
  protected function checkOrigin($origin)
  {
    return true; // Override and return false if the origin is not one that you would expect.
  }
  protected function checkWebsocProtocol($protocol)
  {
    return true; // Override and return false if a protocol is not found that you would expect.
  }
  protected function checkWebsocExtensions($extensions)
  {
    return true; // Override and return false if an extension is not found that you would expect.
  }
  protected function processProtocol($protocol)
  {
    return ""; // return either "Sec-WebSocket-Protocol: SelectedProtocolFromClientList\r\n" or return an empty string.  
    // The carriage return/newline combo must appear at the end of a non-empty string, and must not
    // appear at the beginning of the string nor in an otherwise empty string, or it will be considered part of 
    // the response body, which will trigger an error in the client as it will not be formatted correctly.
  }
  protected function processExtensions($extensions)
  {
    return ""; // return either "Sec-WebSocket-Extensions: SelectedExtensions\r\n" or return an empty string.
  }
  protected function getUserBySocket($socket)
  {
    foreach ($this->users as $user) {
      if ($user->socket == $socket) {
        return $user;
      }
    }
    return null;
  }
  public function stdout($message)
  {
    if ($this->interactive) {
      echo "$message\n";
    }
  }
  public function stderr($message)
  {
    if ($this->interactive) {
      echo "$message\n";
    }
  }
  protected function frame($message, $user, $messageType = 'text', $messageContinues = false)
  {
    switch ($messageType) {
      case 'continuous':
        $b1 = 0;
        break;
      case 'text':
        $b1 = ($user->sendingContinuous) ? 0 : 1;
        break;
      case 'binary':
        $b1 = ($user->sendingContinuous) ? 0 : 2;
        break;
      case 'close':
        $b1 = 8;
        break;
      case 'ping':
        $b1 = 9;
        break;
      case 'pong':
        $b1 = 10;
        break;
    }
    if ($messageContinues) {
      $user->sendingContinuous = true;
    } else {
      $b1 += 128;
      $user->sendingContinuous = false;
    }
    $length = strlen($message);
    $lengthField = "";
    if ($length < 126) {
      $b2 = $length;
    } elseif ($length < 65536) {
      $b2 = 126;
      $hexLength = dechex($length);
      //$this->stdout("Hex Length: $hexLength");
      if (strlen($hexLength) % 2 == 1) {
        $hexLength = '0' . $hexLength;
      }
      $n = strlen($hexLength) - 2;
      for ($i = $n; $i >= 0; $i = $i - 2) {
        $lengthField = chr(hexdec(substr($hexLength, $i, 2))) . $lengthField;
      }
      while (strlen($lengthField) < 2) {
        $lengthField = chr(0) . $lengthField;
      }
    } else {
      $b2 = 127;
      $hexLength = dechex($length);
      if (strlen($hexLength) % 2 == 1) {
        $hexLength = '0' . $hexLength;
      }
      $n = strlen($hexLength) - 2;
      for ($i = $n; $i >= 0; $i = $i - 2) {
        $lengthField = chr(hexdec(substr($hexLength, $i, 2))) . $lengthField;
      }
      while (strlen($lengthField) < 8) {
        $lengthField = chr(0) . $lengthField;
      }
    }
    return chr($b1) . chr($b2) . $lengthField . $message;
  }

  //check packet if he have more than one frame and process each frame individually
  protected function split_packet($length, $packet, $user)
  {
    //add PartialPacket and calculate the new $length
    if ($user->handlingPartialPacket) {
      $packet = $user->partialBuffer . $packet;
      $user->handlingPartialPacket = false;
      $length = strlen($packet);
    }
    $fullpacket = $packet;
    $frame_pos = 0;
    $frame_id = 1;
    while ($frame_pos < $length) {
      $headers = $this->extractHeaders($packet);
      $headers_size = $this->calcoffset($headers);
      $framesize = $headers['length'] + $headers_size;

      //split frame from packet and process it
      $frame = substr($fullpacket, $frame_pos, $framesize);
      if (($message = $this->deframe($frame, $user, $headers)) !== FALSE) {
        if ($user->hasSentClose) {
          $this->disconnect($user->socket);
        } else {
          if ((preg_match('//u', $message)) || ($headers['opcode'] == 2)) {
            //$this->stdout("Text msg encoded UTF-8 or Binary msg\n".$message); 
            $this->process($user, $message);
          } else {
            $this->stderr("not UTF-8\n");
          }
        }
      }
      //get the new position also modify packet data
      $frame_pos += $framesize;
      $packet = substr($fullpacket, $frame_pos);
      $frame_id++;
    }
  }
  protected function calcoffset($headers)
  {
    $offset = 2;
    if ($headers['hasmask']) {
      $offset += 4;
    }
    if ($headers['length'] > 65535) {
      $offset += 8;
    } elseif ($headers['length'] > 125) {
      $offset += 2;
    }
    return $offset;
  }
  protected function deframe($message, &$user)
  {
    //echo $this->strtohex($message);
    $headers = $this->extractHeaders($message);
    $pongReply = false;
    $willClose = false;
    switch ($headers['opcode']) {
      case 0:
      case 1:
      case 2:
        break;
      case 8:
        // todo: close the connection
        $user->hasSentClose = true;
        return "";
      case 9:
        $pongReply = true;
        break;
      case 10:
        break;
      default:
        //$this->disconnect($user); // todo: fail connection
        $willClose = true;
        break;
    }
    /* Deal by split_packet() as now deframe() do only one frame at a time.
    if ($user->handlingPartialPacket) {
    $message = $user->partialBuffer . $message;
    $user->handlingPartialPacket = false;
    return $this->deframe($message, $user);
    }
    */

    if ($this->checkRSVBits($headers, $user)) {
      return false;
    }
    if ($willClose) {
      // todo: fail the connection
      return false;
    }
    $payload = $user->partialMessage . $this->extractPayload($message, $headers);
    if ($pongReply) {
      $reply = $this->frame($payload, $user, 'pong');
      socket_write($user->socket, $reply, strlen($reply));
      return false;
    }
    if ($headers['length'] > strlen($this->applyMask($headers, $payload))) {
      $user->handlingPartialPacket = true;
      $user->partialBuffer = $message;
      return false;
    }
    $payload = $this->applyMask($headers, $payload);
    if ($headers['fin']) {
      $user->partialMessage = "";
      return $payload;
    }
    $user->partialMessage = $payload;
    return false;
  }
  protected function extractHeaders($message)
  {
    $header = array(
      'fin' => $message[0] & chr(128),
      'rsv1' => $message[0] & chr(64),
      'rsv2' => $message[0] & chr(32),
      'rsv3' => $message[0] & chr(16),
      'opcode' => ord($message[0]) & 15,
      'hasmask' => $message[1] & chr(128),
      'length' => 0,
      'mask' => ""
    );
    $header['length'] = (ord($message[1]) >= 128) ? ord($message[1]) - 128 : ord($message[1]);
    if ($header['length'] == 126) {
      if ($header['hasmask']) {
        $header['mask'] = $message[4] . $message[5] . $message[6] . $message[7];
      }
      $header['length'] = ord($message[2]) * 256
        + ord($message[3]);
    } elseif ($header['length'] == 127) {
      if ($header['hasmask']) {
        $header['mask'] = $message[10] . $message[11] . $message[12] . $message[13];
      }
      $header['length'] = ord($message[2]) * 65536 * 65536 * 65536 * 256
        + ord($message[3]) * 65536 * 65536 * 65536
        + ord($message[4]) * 65536 * 65536 * 256
        + ord($message[5]) * 65536 * 65536
        + ord($message[6]) * 65536 * 256
        + ord($message[7]) * 65536
        + ord($message[8]) * 256
        + ord($message[9]);
    } elseif ($header['hasmask']) {
      $header['mask'] = $message[2] . $message[3] . $message[4] . $message[5];
    }
    return $header;
  }
  protected function extractPayload($message, $headers)
  {
    $offset = 2;
    if ($headers['hasmask']) {
      $offset += 4;
    }
    if ($headers['length'] > 65535) {
      $offset += 8;
    } elseif ($headers['length'] > 125) {
      $offset += 2;
    }
    return substr($message, $offset);
  }
  protected function applyMask($headers, $payload)
  {
    $effectiveMask = "";
    if ($headers['hasmask']) {
      $mask = $headers['mask'];
    } else {
      return $payload;
    }
    while (strlen($effectiveMask) < strlen($payload)) {
      $effectiveMask .= $mask;
    }
    while (strlen($effectiveMask) > strlen($payload)) {
      $effectiveMask = substr($effectiveMask, 0, -1);
    }
    return $effectiveMask ^ $payload;
  }
  protected function checkRSVBits($headers, $user)
  {
    if (ord($headers['rsv1']) + ord($headers['rsv2']) + ord($headers['rsv3']) > 0) {
      return true;
    }
    return false;
  }
}
