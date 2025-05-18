const WebSocket = require("ws");
const EventEmitter = require("events");
const Logger = require("./logger");
const crypto = require("crypto");
const readlineSync = require("readline-sync");
const { Mutex } = require("async-mutex");
const http = require("http");

const {
  loginUser,
  validateApiKey,
  getAllOrders,
  createOrder,
  updateOrder,
  getAllDrones,
  updateDrone,
  createDrone,
  getOrderDetails,
  currentlyDelivering
} = require("./api");

const MESSAGE_SIZE = 1024 * 1024;
const SESSION_TIMEOUT = 300 * 60 * 1000;
const RATE_LIMIT = { attempts: 5, window: 5 * 60 * 1000 };
const RESERVED_PORTS = [80, 443, 3306, 8080, 5432];
const PORT_FALLBACK = 4494;
const CACHE_TTL = parseInt(process.env.ORDER_CACHE_TTL_MS, 10) || 10000;

class ServerEvents extends EventEmitter {}
const serverEvents = new ServerEvents();
const usersMutex = new Mutex();
const users = new Map();
const loginAttempts = new Map();
const deliveryStateMutex = new Mutex();
const deliveryState = new Map();
const deliveryRequestsMutex = new Mutex();
const deliveryRequests = new Map();

async function createServer() {
  const port = await getValidPort();
  const server = http.createServer();
  const ws = new WebSocket.Server({
    server,
    maxPayload: MESSAGE_SIZE,
  });

  server.on("error", (error) => {
    if (error.code === "EADDRINUSE") {
      Logger.error(`Port ${port} in use. Trying next valid port.`);
      let newPort = port;
      do {
        newPort++;
      } while (!isValidPort(newPort));
      server.listen(newPort);
    } else {
      Logger.error(`Server error: ${error.message}`);
      process.exit(1);
    }
  });

  server.listen(port, () => {
    Logger.info(`Server running(listening) on ws://localhost:${port}`);
    serverEvents.emit("server_started", port);
  });

  setupWebSocketHandlers(ws);
  setupIntervalTasks(ws);
}

function setupWebSocketHandlers(ws) {
  ws.on("connection", (ws, req) => {
    const sessionId = crypto.randomBytes(32).toString("hex");
    const ip = req.socket.remoteAddress;
    const connectTime = Date.now();
    Logger.info(`New connection from ${ip} (session: ${sessionId})`);

    ws.isAlive = true;
    ws.missedPings = 0;
    ws.on("pong", () => {
      ws.isAlive = true;
      ws.missedPings = 0;
      updateUserActivity(ws.username);
    });

    ws.on("message", async (message) => {
      try {
        const data = parseMessage(message);
        if (data.type === "login") {
          await handleLogin(data, ws, sessionId, req);
        } else {
          if (!ws.username) {
            Logger.warn(`Unauthenticated message received: ${JSON.stringify(data)}`);
            throw new Error("Not authenticated");
          }
          await handleCommand(data, ws);
        }
      } catch (error) {
        handleError(error, ws);
      }
    });

    ws.on("close", () => {
      cleanupConnection(ws, connectTime);
    });
  });
}

function setupIntervalTasks(ws) {
  setInterval(() => {
    ws.clients.forEach((ws) => {
      if (!ws.isAlive) {
        ws.missedPings++;
        if (ws.missedPings >= 5) {
          return ws.terminate();
        }
      }
      ws.isAlive = false;
      ws.ping();
    });
  }, 30000);

  setInterval(() => {
    usersMutex.runExclusive(() => {
      const now = Date.now();
      for (const [email, user] of users) {
        if (now - user.lastActivity > SESSION_TIMEOUT) {
          Logger.info({
            timestamp: new Date().toISOString(),
            level: "info",
            message: `Session timeout for ${email.replace(/(.{3}).*@/, "$1****@")}`,
            context: { sessionId: user.sessionId },
          });
          user.ws.close();
          users.delete(email);
        }
      }
    });
  }, 10 * 1000);

  setInterval(async () => {
    await updateDeliveryStatus();
  }, 5000);
}

async function getValidPort() {
  let port = parseInt(process.env.MY_PORT || process.argv[2] || PORT_FALLBACK, 10);
  while (!isValidPort(port)) {
    Logger.warn(`Invalid port ${port}. Must be between 1024 and 49151, and not reserved.`);
    port = readlineSync.questionInt("Enter port (1024-49151): ", {
      min: 1024,
      max: 49151,
    });
  }
  return port;
}

function isValidPort(port) {
  return (
    !isNaN(port) &&
    port >= 1024 &&
    port <= 49151 &&
    !RESERVED_PORTS.includes(port)
  );
}

function parseMessage(message) {
  const raw = message.toString('utf8');
  if (raw.length > MESSAGE_SIZE) throw new Error('Message too large');
  if (raw.includes('\0')) throw new Error('Null bytes detected');

  try {
    const data = JSON.parse(raw);
    if (!data.type && !data.command) throw new Error('Missing message type or command');
    if (data.type === 'login') {
      if (!data.email || typeof data.email !== 'string')
        throw new Error('Missing or invalid email');
      if (!data.password || typeof data.password !== 'string')
        throw new Error('Missing or invalid password');
    } else if (data.type === 'keep_alive') {
      return data;
    } else if (data.type === 'command' && data.command) {
      // Validate commands
      switch (data.command.toUpperCase()) {
        case 'CREATE_ORDER':
          if (!data.destination_latitude || !data.destination_longitude || !Array.isArray(data.products)) {
            throw new Error('Missing required fields: destination_latitude, destination_longitude, products');
          }
          break;
        case 'START_DELIVERY':
          if (!data.order_id || !data.drone_id) {
            throw new Error('Missing required fields: order_id, drone_id');
          }
          break;
        case 'REQUEST_DELIVERY':
          if (!data.order_id) {
            throw new Error('Missing required field: order_id');
          }
          break;
        case 'GET_DELIVERY_REQUESTS':
        case 'GET_ORDERS':
        case 'CURRENTLY_DELIVERING':
        case 'DRONE_STATUS':
        case 'CREATE_DRONE':
        case 'KILL':
        case 'QUIT':
          break;
        default:
          throw new Error('Invalid command');
      }
    } else {
      throw new Error('Invalid message format');
    }
    return data;
  } catch (e) {
    throw new Error('Invalid JSON format');
  }
}

function handleError(error, ws) {
  Logger.error(`Client error: ${error.message}`);
  try {
    ws.send(JSON.stringify({ type: "error", message: error.message }));
  } catch (e) {
    Logger.warn("Failed to send error to client");
  }
}

function updateUserActivity(username) {
  if (!username) return;
  usersMutex.runExclusive(() => {
    const user = users.get(username);
    if (user) user.lastActivity = Date.now();
  });
}

async function cleanupConnection(ws, connectTime) {
  if (!ws.username) return;
  const duration = (Date.now() - connectTime) / 1000;
  Logger.info({
    timestamp: new Date().toISOString(),
    level: "info",
    message: `User ${ws.username.replace(/(.{3}).*@/, "$1****@")} disconnected`,
    context: { duration },
  });

  const user = await usersMutex.runExclusive(() => {
    const u = users.get(ws.username);
    users.delete(ws.username);
    return u;
  });

  if (user.userType === "Courier" || user.userType === "Distributor") {
    const drones = await getAllDrones(user.apiKey);
    const operatedDrones = drones.filter((d) => d.current_operator_id === user.id);

    for (const drone of operatedDrones) {
      const isDelivering = [...deliveryState.values()].some((d) => d.drone_id === drone.id);
      if (!isDelivering) continue;

      await updateDrone(user.apiKey, drone.id, { is_available: false });

      const deliveries = [];
      await deliveryStateMutex.runExclusive(() => {
        for (const [order_id, delivery] of deliveryState) {
          if (delivery.drone_id === drone.id) {
            deliveries.push({ order_id, customer_email: delivery.customer_email });
            deliveryState.delete(order_id);
          }
        }
      });

      for (const { order_id, customer_email } of deliveries) {
        await updateOrder(user.apiKey, order_id, "Storage");
        const customer = users.get(customer_email);
        if (customer) {
          customer.ws.send(
            JSON.stringify({
              type: "notification",
              message: `Order ${order_id} delivery postponed due to operator disconnection. Drone ${drone.id} has been grounded.`,
            })
          );
        }
      }
    }
  }
}

async function handleLogin(data, ws, sessionId, req) {
  if (!data.email || !data.password) {
    throw new Error("Email and password required");
  }

  const ip = req.socket.remoteAddress;
  const attempts = loginAttempts.get(ip) || { count: 0, timestamp: Date.now() };
  if (Date.now() - attempts.timestamp > RATE_LIMIT.window) {
    attempts.count = 0;
    attempts.timestamp = Date.now();
  }
  if (attempts.count >= RATE_LIMIT.attempts) {
    throw new Error(
      `Too many attempts. Try again in ${Math.ceil((RATE_LIMIT.window - (Date.now() - attempts.timestamp)) / 60000)} minutes`
    );
  }
  attempts.count++;
  loginAttempts.set(ip, attempts);

  const loginResponse = await loginUser(data.email, data.password);
  if (!loginResponse?.apikey) throw new Error("Authentication failed");

  const userInfo = await validateApiKey(loginResponse.apikey);
  if (!userInfo) throw new Error("Invalid API key");

  // Normalize userType
  const normalizedUserType = userInfo.user_type.charAt(0).toUpperCase() + userInfo.user_type.slice(1).toLowerCase();

  await usersMutex.runExclusive(() => {
    if (users.has(data.email)) throw new Error("User already connected");

    users.set(data.email, {
      ws,
      sessionId,
      userType: normalizedUserType,
      apiKey: loginResponse.apikey,
      lastActivity: Date.now(),
      id: userInfo.id,
      orderCache: { data: null, timestamp: 0, ttl: CACHE_TTL },
    });
  });

  ws.username = data.email;
  ws.send(
    JSON.stringify({
      type: "login_success",
      sessionId,
      userType: normalizedUserType,
      name: userInfo.name,
      surname: userInfo.surname,
    })
  );
  Logger.info(`${data.email} logged in as ${normalizedUserType} (session: ${sessionId})`);
}

async function handleCommand(data, ws) {
  const user = users.get(ws.username);
  if (!user) throw new Error("Session expired");
  Logger.info(`Handling command: ${data.command} for user: ${ws.username}, userType: ${user.userType}`);
  if (data.type === "keep_alive") {
    updateUserActivity(ws.username);
    ws.send(JSON.stringify({ type: "keep_alive_response", status: "success" }));
    return;
  }

  switch (data.command?.toUpperCase()) {
    case "KILL":
      if (user.userType !== "Distributor") throw new Error("Permission denied");
      await handleKillCommand(data, user, ws);
      break;
    case "QUIT":
      await handleQuitCommand();
      break;
    case "GET_ORDERS":
      await handleGetOrders(ws, user);
      break;
    case "CREATE_ORDER":
      if (user.userType !== "Customer") throw new Error("Permission denied");
      await handleCreateOrder(data, ws, user);
      break;
    case "CURRENTLY_DELIVERING":
      if (!["Customer", "Courier", "Distributor"].includes(user.userType))
        throw new Error("Permission denied");
      await handleCurrentlyDelivering(ws, user);
      break;
    case "DRONE_STATUS":
      if (!["Courier", "Distributor"].includes(user.userType))
        throw new Error("Permission denied");
      await handleDroneStatus(ws, user, data);
      break;
    case "START_DELIVERY":
      if (!["Courier", "Distributor"].includes(user.userType)) throw new Error("Permission denied");
      await handleStartDelivery(data, ws, user);
      break;
    case "REQUEST_DELIVERY":
      await handleRequestDelivery(data, ws, user);
      break;
    case "GET_DELIVERY_REQUESTS":
      await handleGetDeliveryRequests(ws, user);
      break;
    case "CREATE_DRONE":
      if (!["Courier", "Distributor"].includes(user.userType))
        throw new Error("Permission denied");
      await handleCreateDrone(data, ws, user);
      break;
    default:
      throw new Error("Invalid command");
  }
}

async function handleRequestDelivery(data, ws, user) {
  Logger.info(`Handling REQUEST_DELIVERY for user: ${user.ws.username}, userType: ${user.userType}, order_id: ${data.order_id}`);
  
  // Normalize userType to match client-side (Customer, Courier, Distributor)
  const normalizedUserType = user.userType.charAt(0).toUpperCase() + user.userType.slice(1).toLowerCase();
  if (normalizedUserType !== "Customer") {
    Logger.error(`Permission denied: User ${user.ws.username} is ${normalizedUserType}, expected Customer`);
    throw new Error("Permission denied");
  }
  if (!data.order_id) {
    Logger.error(`Missing order_id for REQUEST_DELIVERY by ${user.ws.username}`);
    throw new Error("Missing order_id");
  }

  const orders = await getAllOrders(user.apiKey);
  const order = orders.find((o) => o.order_id === parseInt(data.order_id));
  if (!order) {
    Logger.error(`Order ${data.order_id} not found for user ${user.ws.username}`);
    throw new Error("Order not found");
  }
  if (order.state !== "Storage") {
    Logger.error(`Order ${data.order_id} is in state ${order.state}, expected Storage`);
    throw new Error("Order not in Storage state");
  }

  await deliveryRequestsMutex.runExclusive(() => {
    deliveryRequests.set(data.order_id, {
      order_id: data.order_id,
      customer_email: user.ws.username,
      timestamp: Date.now(),
    });
    Logger.info(`Stored delivery request for order ${data.order_id} by ${user.ws.username}`);
  });

  await usersMutex.runExclusive(() => {
    for (const [email, u] of users) {
      if (["Courier", "Distributor"].includes(u.userType)) {
        u.ws.send(
          JSON.stringify({
            type: "notification",
            message: `New delivery request for order ${data.order_id} from ${user.ws.username}`,
          })
        );
        Logger.info(`Notified ${email} of delivery request for order ${data.order_id}`);
      }
    }
  });

  ws.send(
    JSON.stringify({
      type: "command_result",
      status: "success",
      message: `Delivery request for order ${data.order_id} sent`,
    })
  );
  Logger.info(`Delivery request for order ${data.order_id} by ${user.ws.username} processed successfully`);
}

async function handleGetDeliveryRequests(ws, user) {
  if (!["Courier", "Distributor"].includes(user.userType)) {
    throw new Error("Permission denied");
  }

  let requests = [];
  await deliveryRequestsMutex.runExclusive(() => {
    requests = [...deliveryRequests.values()];
  });

  ws.send(
    JSON.stringify({
      type: "delivery_requests",
      data: requests,
    })
  );
  Logger.info(`Delivery requests sent to ${user.ws.username}: ${requests.length} requests`);
}

async function handleKillCommand(data, user, ws) {
  await usersMutex.runExclusive(() => {
    const target = users.get(data.targetEmail);
    if (!target) throw new Error("User not found");

    target.ws.send(
      JSON.stringify({
        type: "notification",
        message: data.reason || "Disconnected by admin",
      })
    );
    target.ws.close();
    users.delete(data.targetEmail);

    ws.send(
      JSON.stringify({
        type: "command_result",
        status: "success",
        message: `${data.targetEmail} disconnected`,
      })
    );
    Logger.info(`User ${data.targetEmail} killed by ${user.ws.username}: ${data.reason || "Disconnected by admin"}`);
  });
}

async function handleQuitCommand() {
  await usersMutex.runExclusive(() => {
    const msg = JSON.stringify({ type: "notification", message: "Server shutting down" });
    for (const user of users.values()) {
      try {
        user.ws.send(msg);
        user.ws.close();
      } catch (e) {
        Logger.warn(`Failed to notify ${user.ws.username}`);
      }
    }
    Logger.info(`Server shutdown. Disconnected users: ${[...users.keys()].join(", ")}`);
    users.clear();
    process.exit(0);
  });
}

async function handleGetOrders(ws, user) {
  if (!["Customer", "Courier", "Distributor"].includes(user.userType)) {
    throw new Error("Permission denied");
  }

  const orders =
    user.orderCache.data && Date.now() - user.orderCache.timestamp < user.orderCache.ttl
      ? user.orderCache.data
      : await getAllOrders(user.apiKey);
  user.orderCache.data = orders;
  user.orderCache.timestamp = Date.now();

  ws.send(
    JSON.stringify({
      type: "orders",
      data: orders,
      filter: user.userType === "Courier" || user.userType === "Distributor" ? "all" : "user-specific",
    })
  );
  Logger.info({
    timestamp: new Date().toISOString(),
    level: "info",
    message: `Orders sent to ${user.ws.username.replace(/(.{3}).*@/, "$1****@")}`,
    context: { userType: user.userType, orderCount: orders.length, filter: user.userType === "Courier" || user.userType === "Distributor" ? "all" : "user-specific" },
  });
}

async function handleCreateOrder(data, ws, user) {
  if (!data.destination_latitude || !data.destination_longitude || !data.products) {
    throw new Error("Missing required fields: destination_latitude, destination_longitude, products");
  }
  if (!Array.isArray(data.products) || data.products.length === 0 || data.products.length > 7) {
    throw new Error("Products must be a non-empty array with at most 7 items");
  }
  for (const product of data.products) {
    if (!product.product_id || !product.quantity || !Number.isInteger(product.product_id) || !Number.isInteger(product.quantity) || product.quantity <= 0) {
      throw new Error("Each product must have a valid product_id and positive quantity");
    }
  }

  const order = await createOrder(user.apiKey, parseFloat(data.destination_latitude), parseFloat(data.destination_longitude), data.products);

  user.orderCache.data = null;
  user.orderCache.timestamp = 0;

  ws.send(
    JSON.stringify({
      type: "command_result",
      status: "success",
      message: `Order created with ID ${order.order_id}`,
      data: order,
    })
  );
  Logger.info(`Order ${order.order_id} created by ${user.ws.username}`);
}

async function handleCurrentlyDelivering(ws, user) {
    try {
        const orders = await currentlyDelivering(user.apiKey);
        ws.send(JSON.stringify({ type: "currently_delivering", data: orders }));
        Logger.info(`Currently delivering orders sent to ${user.ws.username}: ${orders.length} orders`);
    } catch (error) {
        Logger.error(`CURRENTLY_DELIVERING failed for ${user.ws.username}: ${error.message}`);
        ws.send(JSON.stringify({ type: "error", message: `Failed to retrieve delivering orders: ${error.message}` }));
    }
}

async function handleCreateDrone(data, ws, user) {
    if (typeof data.latest_latitude !== 'undefined' && (typeof data.latest_latitude !== 'number' || data.latest_latitude < -90 || data.latest_latitude > 90)) {
        throw new Error("Invalid latitude (must be between -90 and 90)");
    }
    if (typeof data.latest_longitude !== 'undefined' && (typeof data.latest_longitude !== 'number' || data.latest_longitude < -180 || data.latest_longitude > 180)) {
        throw new Error("Invalid longitude (must be between -180 and 180)");
    }
    if (typeof data.altitude !== 'undefined' && (typeof data.altitude !== 'number' || data.altitude < 0)) {
        throw new Error("Invalid altitude (must be non-negative)");
    }
    if (typeof data.battery_level !== 'undefined' && (typeof data.battery_level !== 'number' || data.battery_level < 0 || data.battery_level > 100)) {
        throw new Error("Invalid battery level (must be between 0 and 100)");
    }
    if (typeof data.is_available !== 'undefined' && typeof data.is_available !== 'boolean') {
        throw new Error("Invalid is_available (must be boolean)");
    }

    const options = {
        current_operator_id: user.id,
    };
    if (typeof data.latest_latitude !== 'undefined') options.latest_latitude = data.latest_latitude;
    if (typeof data.latest_longitude !== 'undefined') options.latest_longitude = data.latest_longitude;
    if (typeof data.altitude !== 'undefined') options.altitude = data.altitude;
    if (typeof data.battery_level !== 'undefined') options.battery_level = data.battery_level;
    if (typeof data.is_available !== 'undefined') options.is_available = data.is_available;

    const drone = await createDrone(user.apiKey, options);

    if (data.order_id) {
        const orders = await getAllOrders(user.apiKey);
        const order = orders.find((o) => o.order_id === parseInt(data.order_id) && o.state === "Storage");
        if (!order) {
            throw new Error("Order not found or not in Storage state");
        }
        await deliveryStateMutex.runExclusive(() => {
            deliveryState.set(data.order_id, {
                drone_id: drone.id,
                customer_email: order.customer_email || user.ws.username,
                reserved: true
            });
        });
    }

    ws.send(
        JSON.stringify({
            type: "command_result",
            status: "success",
            message: `Drone created with ID ${drone.id}`,
            data: drone,
        })
    );
    Logger.info(`Drone ${drone.id} created by ${user.ws.username} with order_id: ${data.order_id || 'none'}`);
}

async function handleDroneStatus(ws, user, data = {}) {
  const drones = await getAllDrones(user.apiKey);
  Logger.info(`Raw drones from getAllDrones for ${user.ws.username}: ${JSON.stringify(drones)}`);
  const result = drones
    .filter((drone) => {
      if (user.userType === 'Distributor') return true;
      if (drone.current_operator_id !== user.id) return false;
      if (data.is_available !== undefined) return drone.is_available === data.is_available;
      return true;
    })
    .map((drone) => {
      let order_id = null;
      for (const [oid, delivery] of deliveryState) {
        if (delivery.drone_id === drone.id) {
          order_id = oid;
          break;
        }
      }
      return {
        id: drone.id,
        battery_level: drone.battery_level,
        altitude: drone.altitude,
        current_operator: { name: drone.operator_name || 'None', surname: drone.operator_surname || 'None' },
        gps_coordinates: [drone.latest_latitude, drone.latest_longitude],
        is_delivering: [...deliveryState.values()].some((d) => d.drone_id === drone.id && !d.reserved),
        is_available: drone.is_available,
        order_id
      };
    });

  ws.send(JSON.stringify({ type: 'drone_status', data: result }));
  Logger.info({
    timestamp: new Date().toISOString(),
    level: 'info',
    message: `Drone status sent to ${user.ws.username.replace(/(.{3}).*@/, '$1****@')}`,
    context: { droneCount: result.length, filters: { ...data, current_operator_id: user.id } },
  });
}

async function handleStartDelivery(data, ws, user) {
  if (!data.order_id || !data.drone_id) {
    throw new Error("Missing required fields: order_id, drone_id");
  }

  const orders = await getAllOrders(user.apiKey);
  const order = orders.find((o) => o.order_id === parseInt(data.order_id));
  if (!order || order.state !== "Storage") {
    throw new Error("Order not found or not in Storage state");
  }

  const drones = await getAllDrones(user.apiKey);
  const drone = drones.find((d) => d.id === parseInt(data.drone_id) && d.is_available && d.current_operator_id === user.id);
  if (!drone) {
    throw new Error("Drone not found, not available, or not operated by you");
  }
  if (drone.battery_level < 20) {
    throw new Error("Drone battery too low");
  }

  let linked_order_id = null;
  await deliveryStateMutex.runExclusive(() => {
    for (const [oid, delivery] of deliveryState) {
      if (delivery.drone_id === drone.id) {
        linked_order_id = oid;
        break;
      }
    }
  });
  if (linked_order_id && linked_order_id !== parseInt(data.order_id)) {
    throw new Error(`Drone ${drone.id} is reserved for order ${linked_order_id}`);
  }

  await updateOrder(user.apiKey, order.order_id, "Out for delivery");
  user.orderCache.data = null;
  user.orderCache.timestamp = 0;

  await updateDrone(user.apiKey, drone.id, { is_available: false });

  const recipient = await getOrderDetails(user.apiKey, order.customer_id);
  const customer_email = recipient.email || ws.username;
  await deliveryStateMutex.runExclusive(() => {
    deliveryState.set(order.order_id, { drone_id: drone.id, customer_email, reserved: false });
  });

  await deliveryRequestsMutex.runExclusive(() => {
    deliveryRequests.delete(data.order_id);
  });

  const customer = users.get(customer_email);
  if (customer) {
    customer.ws.send(
      JSON.stringify({
        type: "notification",
        message: `Your order ${order.order_id} is now Out for delivery`,
      })
    );
  }

  ws.send(
    JSON.stringify({
      type: "command_result",
      status: "success",
      message: `Delivery started for order ${order.order_id} with drone ${drone.id}`,
    })
  );
  Logger.info({
    timestamp: new Date().toISOString(),
    level: "info",
    message: `Delivery started for order ${order.order_id} by ${user.ws.username.replace(/(.{3}).*@/, "$1****@")}`,
    context: { drone_id: drone.id },
  });
}

async function updateDeliveryStatus() {
  await deliveryStateMutex.runExclusive(async () => {
    for (const [order_id, { drone_id, customer_email, reserved }] of deliveryState) {
      if (reserved) continue; // Skip reserved drones not yet delivering
      const user = users.get(customer_email);
      if (!user) continue;

      const orders = await getAllOrders(user.apiKey);
      const order = orders.find((o) => o.order_id === order_id);
      if (!order || order.state !== "Out for delivery") continue;

      const drones = await getAllDrones(user.apiKey);
      const drone = drones.find((d) => d.id === drone_id);
      if (!drone) continue;

      let canMove = true;
      for (const otherDrone of drones) {
        if (otherDrone.id === drone.id) continue;
        const distance =
          Math.sqrt(
            Math.pow(drone.latest_latitude - otherDrone.latest_latitude, 2) +
            Math.pow(drone.latest_longitude - otherDrone.latest_longitude, 2)
          ) * 111000;
        if (distance < 10 && Math.abs(drone.altitude - otherDrone.altitude) < 5) {
          canMove = false;
          Logger.warn({
            timestamp: new Date().toISOString(),
            level: "warn",
            message: `Collision risk for drone ${drone.id}`,
            context: {
              otherDroneId: otherDrone.id,
              distance,
              altitudeDiff: Math.abs(drone.altitude - otherDrone.altitude),
            },
          });
          break;
        }
      }

      if (!canMove) continue;

      let { latest_latitude, latest_longitude } = drone;
      const dest_lat = order.destination_latitude;
      const dest_lon = order.destination_longitude;

      const speed = 10 / 111000;
      const distance =
        Math.sqrt(
          Math.pow(dest_lat - latest_latitude, 2) +
          Math.pow(dest_lon - latest_longitude, 2)
        ) * 111000;
      const timeToDest = distance / 10;
      const delta_lat = ((dest_lat - latest_latitude) / timeToDest) * 5;
      const delta_lon = ((dest_lon - latest_longitude) / timeToDest) * 5;

      if (Math.random() < 0.1) continue;

      latest_latitude += delta_lat || 0;
      latest_longitude += delta_lon || 0;

      const movedDistance =
        Math.sqrt(
          Math.pow(delta_lat * 111000, 2) + Math.pow(delta_lon * 111000, 2)
        ) / 1000;
      const battery_level = Math.max(0, drone.battery_level - movedDistance * 0.1);

      if (battery_level <= 0) {
        await updateDrone(user.apiKey, drone_id, { is_available: false });
        await updateOrder(user.apiKey, order_id, "Storage");
        deliveryState.delete(order_id);
        user.ws.send(
          JSON.stringify({
            type: "notification",
            message: `Order ${order_id} delivery failed due to drone battery depletion`,
          })
        );
        continue;
      }

      await updateDrone(user.apiKey, drone_id, {
        latest_latitude,
        latest_longitude,
        altitude: drone.altitude || 100,
        battery_level,
      });

      if (
        Math.abs(dest_lat - latest_latitude) < 0.001 &&
        Math.abs(dest_lon - latest_longitude) < 0.001
      ) {
        await updateOrder(user.apiKey, order_id, "Delivered");
        deliveryState.delete(order_id);
        user.ws.send(
          JSON.stringify({
            type: "notification",
            message: `Order ${order_id} has been delivered`,
          })
        );
      }
    }
  });
}

createServer().catch((err) => {
  Logger.error(`Server failed: ${err.message}`);
  process.exit(1);
});

module.exports = { users, serverEvents };