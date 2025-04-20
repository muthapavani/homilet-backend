const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bcrypt = require("bcrypt");
const multer = require("multer");
const path = require("path");
const fs = require("fs").promises;
const fsSync = require("fs");
const Razorpay = require('razorpay');
const crypto = require('crypto');
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Fixed CORS configuration (removed duplicate CORS setup)
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = ['https://homiletfrontend-dmtr.vercel.app','http://localhost:5173', 'http://localhost:5174'];
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log("Blocked origin:", origin);
      callback(new Error('CORS policy violation'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));

// Ensure required environment variables exist
if (!process.env.JWT_SECRET) {
  console.error(" Critical Error: JWT_SECRET environment variable is required");
  process.exit(1);
}

// Create necessary directories
  const uploadDir = path.join(__dirname, "uploads");
  const publicDir = path.join(__dirname, "public");

  try {
    if (!fsSync.existsSync(uploadDir)) {
      fsSync.mkdirSync(uploadDir, { recursive: true });
      console.log(" Created uploads directory");
    }
  
  if (!fsSync.existsSync(publicDir)) {
    fsSync.mkdirSync(publicDir, { recursive: true });
    console.log(" Created public directory");
  }
} catch (err) {
  console.error(" Error creating directories:", err);
  process.exit(1);
}

app.use("/uploads", express.static(uploadDir));

// Request logging for development
if (process.env.NODE_ENV !== 'production') {
  app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
  });
}

const saltRounds = 10;
const JWT_SECRET = process.env.JWT_SECRET || "your_secret_key"; 

// Database Connection Pool
const pool = mysql.createPool({
  host: "my-db.c9w6ssg6i83x.eu-north-1.rds.amazonaws.com",
  user: "pavani",
  password: "12345678",
  database: "homilet",
  waitForConnections: true,
  connectionLimit: 20,          // Increased from 10
  queueLimit: 0,
  enableKeepAlive: true,        // Keep connections alive
  keepAliveInitialDelay: 10000, // 10 seconds
  connectTimeout: 15000,        // 15 seconds connection timeout

});

// Error Handling Utility
const handleDatabaseError = (res, error, defaultMessage = "An error occurred") => {
  console.error("Database Error:", error);
  res.status(500).json({ 
    success: false, 
    message: defaultMessage,
    error: error.message 
  });
};

// Update the database init function to include payment setup
(async function initDatabase() {
  try {
    const connection = await pool.getConnection();
    console.log(" Connected to MySQL Database");
    
    // Check if user1 table exists, create if not
    try {
      await connection.query(`
        SELECT 1 FROM user1 LIMIT 1
      `);
      console.log(" user1 table exists");
      
      // Check and update user1 table structure
      await connection.query(`
        SHOW COLUMNS FROM user1 LIKE 'phone'
      `).then(async ([results]) => {
        if (results.length === 0) {
          console.log("Adding additional profile columns to user1 table...");
          await connection.query(`
            ALTER TABLE user1
            ADD COLUMN  IF NOT EXISTS phone VARCHAR(20) DEFAULT NULL,
            ADD COLUMN  IF NOT EXISTS address TEXT DEFAULT NULL,
            ADD COLUMN  IF NOT EXISTS role ENUM('tenant', 'landlord') DEFAULT 'tenant'
          `);
          console.log(" Added profile columns to user1 table");
        } else {
          console.log(" Profile columns already exist in user1 table");
        }
      });
      
      await connection.query(`
        SHOW COLUMNS FROM user1 LIKE 'is_guest'
      `).then(async ([results]) => {
        if (results.length === 0) {
          console.log("Adding guest account columns to user1 table...");
          await connection.query(`
            ALTER TABLE user1
            ADD COLUMN IF NOT EXISTS is_guest BOOLEAN DEFAULT FALSE,
            ADD COLUMN IF NOT EXISTS guest_expiry_date DATETIME DEFAULT NULL
          `);
          console.log(" Added guest account columns to user1 table");
        } else {
          console.log(" Guest account columns already exist in user1 table");
        }
      });

    } catch (error) {
      // Table doesn't exist, create it
      console.log("Creating user1 table...");
      await connection.query(`
        CREATE TABLE  IF NOT EXISTS  user1 (
          id INT AUTO_INCREMENT PRIMARY KEY,
          name VARCHAR(100) NOT NULL,
          email VARCHAR(100) NOT NULL UNIQUE,
          password VARCHAR(100) NOT NULL,
          phone VARCHAR(20) DEFAULT NULL,
          address TEXT DEFAULT NULL,
          role ENUM('tenant', 'landlord') DEFAULT 'tenant',
          is_guest BOOLEAN DEFAULT FALSE,
          guest_expiry_date DATETIME DEFAULT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      console.log(" Created user1 table");
    }
    
    // Check if properties table exists, create if not
    try {
      await connection.query(`
        SELECT 1 FROM home_let_app_properties LIMIT 1
      `);
      console.log(" home_let_app_properties table exists");
      
      // Check and update property table structure
      await connection.query(`
        SHOW COLUMNS FROM home_let_app_properties LIKE 'latitude'
      `).then(async ([results]) => {
        if (results.length === 0) {
          console.log("Adding latitude and longitude columns to database...");
          await connection.query(`
            ALTER TABLE home_let_app_properties
            ADD COLUMN IF NOT EXISTS latitude DECIMAL(10,8) DEFAULT NULL,
            ADD COLUMN IF NOT EXISTS longitude DECIMAL(11,8) DEFAULT NULL
          `);
          console.log(" Added latitude and longitude columns to database");
        } else {
          console.log(" Location columns already exist in database");
        }
      });
    } catch (error) {
      // Table doesn't exist, create it
      console.log("Creating home_let_app_properties table...");
      await connection.query(`
        CREATE TABLE  IF NOT EXISTS home_let_app_properties (
          id INT AUTO_INCREMENT PRIMARY KEY,
          user_id INT NOT NULL,
          title VARCHAR(255) NOT NULL,
          description TEXT NOT NULL,
          property_type VARCHAR(50) DEFAULT NULL,
          listing_type VARCHAR(50) DEFAULT NULL,
          price DECIMAL(10,2) NOT NULL,
          bedrooms INT DEFAULT NULL,
          bathrooms INT DEFAULT NULL,
          area DECIMAL(10,2) DEFAULT NULL,
          address VARCHAR(255) NOT NULL,
          city VARCHAR(100) NOT NULL,
          state VARCHAR(100) NOT NULL,
          pincode VARCHAR(20) NOT NULL,
          latitude DECIMAL(10,8) DEFAULT NULL,
          longitude DECIMAL(11,8) DEFAULT NULL,
          amenities JSON DEFAULT NULL,
          images JSON DEFAULT NULL,
          status ENUM('active', 'inactive', 'rented', 'sold') DEFAULT 'active',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES user1(id) ON DELETE CASCADE
        )
          
      `);
      console.log(" Created home_let_app_properties table");
    }
    
    // Check if contact_messages table exists, create if not
    try {
      await connection.query(`
        SELECT 1 FROM contact_messages LIMIT 1
      `);
      console.log(" contact_messages table exists");
    } catch (error) {
      console.log("Creating contact_messages table...");
      await connection.query(`
        CREATE TABLE  IF NOT EXISTS  contact_messages (
          id INT AUTO_INCREMENT PRIMARY KEY,
          sender_id INT NOT NULL,
          receiver_id INT NOT NULL,
          property_id INT,
          subject VARCHAR(255) NOT NULL,
          message TEXT NOT NULL,
          is_read BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (sender_id) REFERENCES user1(id) ON DELETE CASCADE,
          FOREIGN KEY (receiver_id) REFERENCES user1(id) ON DELETE CASCADE,
          FOREIGN KEY (property_id) REFERENCES home_let_app_properties(id) ON DELETE SET NULL
        )
      `);
      console.log(" Created contact_messages table");
    }
    
    // Check if payment_orders table exists, create if not
    try {
      await connection.query(`
        SELECT 1 FROM home_let_app_payment_orders LIMIT 1
      `);
      console.log(" home_let_app_payment_orders table exists");
    } catch (error) {
      // Table doesn't exist, create it
      console.log("Creating payment_orders table...");
      await connection.query(`
        CREATE TABLE  IF NOT EXISTS   home_let_app_payment_orders (
          id INT AUTO_INCREMENT PRIMARY KEY,
          order_id VARCHAR(255) NOT NULL UNIQUE,
          property_id INT NOT NULL,
          user_id INT NOT NULL,
          amount DECIMAL(10,2) NOT NULL,
          currency VARCHAR(10) NOT NULL DEFAULT 'INR',
          status VARCHAR(50) NOT NULL DEFAULT 'created',
          payment_id VARCHAR(255),
          created_at DATETIME NOT NULL,
          updated_at DATETIME,
          INDEX idx_property_user (property_id, user_id),
          INDEX idx_status (status),
          INDEX idx_created_at (created_at),
          FOREIGN KEY (property_id) REFERENCES home_let_app_properties(id) ON DELETE CASCADE,
          FOREIGN KEY (user_id) REFERENCES user1(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
      `);
      console.log(" Created home_let_app_payment_orders table");
    }
    
    // Check if payment_history table exists, create if not
    try {
      await connection.query(`
        SELECT 1 FROM home_let_app_payment_history LIMIT 1
      `);
      console.log(" home_let_app_payment_history table exists");
    } catch (error) {
      console.log("Creating payment_history table...");
      await connection.query(`
        CREATE TABLE  IF NOT EXISTS  home_let_app_payment_history (
          id INT AUTO_INCREMENT PRIMARY KEY,
          user_id INT NOT NULL,
          property_id INT NOT NULL,
          order_id VARCHAR(255) NOT NULL,
          payment_id VARCHAR(255) NOT NULL,
          amount DECIMAL(10,2) NOT NULL,
          currency VARCHAR(10) NOT NULL DEFAULT 'INR',
          payment_type ENUM('listing', 'rent', 'deposit', 'other') DEFAULT 'listing',
          notes TEXT,
          created_at DATETIME NOT NULL,
          INDEX idx_user_id (user_id),
          INDEX idx_property_id (property_id),
          INDEX idx_created_at (created_at),
          FOREIGN KEY (property_id) REFERENCES home_let_app_properties(id) ON DELETE CASCADE,
          FOREIGN KEY (user_id) REFERENCES user1(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
      `);
      console.log(" Created home_let_app_payment_history table");
    }
    
    // Try to setup scheduler for payment history cleanup
    try {
     
      await connection.query(`
        CREATE EVENT IF NOT EXISTS clear_old_homelet_payment_history
        ON SCHEDULE EVERY 1 DAY
        DO
        BEGIN
          DELETE FROM home_let_app_payment_history WHERE created_at < DATE_SUB(NOW(), INTERVAL 180 DAY);
        END
      `);
      console.log(" Set up payment history cleanup scheduler");
    } catch (eventErr) {
      console.warn(" Could not setup scheduler:", eventErr.message);
    }
    
    connection.release();
  } catch (err) {
    console.error(" Database initialization failed:", err.message);
    process.exit(1);
  }
})();

// Nodemailer Configuration
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "muttapavani9@gmail.com",
    pass: "chfa vwoa cfhu xsyw",
  },
});

// Temporary OTP Store
const otpStore = {};

// Generate OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|webp/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error("Only image files are allowed!"));
  }
});
// JWT Authentication middleware
const SECRET_KEY = process.env.JWT_SECRET;

// Verification Token Middleware
const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  console.log('Received authorization header:', authHeader ? 'Auth header exists' : 'No auth header'); 
  
  if (!authHeader) {
    return res.status(403).json({ 
      success: false,
      message: "Authentication required",
      details: "No authorization header provided"
    });
  }
  
  try {
    const tokenParts = authHeader.split(" ");
    console.log('Token parts length:', tokenParts.length); 
    if (tokenParts.length !== 2 || tokenParts[0] !== "Bearer") {
      return res.status(401).json({ 
        success: false,
        message: "Invalid authentication format",
        details: "Authorization header must be in format: Bearer [token]"
      });
    }
    
    const token = tokenParts[1].trim(); // Trim whitespace
    
    // Check if token is empty or malformed
    if (!token || token === "null" || token === "undefined") {
      return res.status(401).json({ 
        success: false,
        message: "Invalid token",
        details: "Token cannot be empty, null, or undefined"
      });
    }
    
    console.log('Attempting to verify token'); // Debug verification
    
    const decoded = jwt.verify(token, SECRET_KEY);
    console.log('Token verified successfully:', decoded); // Debug decoded token
    
    // Make sure both id and userId are available for consistent use
    req.user = {
      ...decoded,
      id: decoded.id || decoded.userId,
      userId: decoded.userId || decoded.id
    };
    
    console.log('Decoded user:', req.user);
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false,
        message: "Token expired", 
        details: "Please log in again",
        expiredAt: error.expiredAt 
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false,
        message: "Invalid token", 
        details: error.message 
      });
    }
    
    if (error.name === 'NotBeforeError') {
      return res.status(401).json({ 
        success: false,
        message: "Token not active yet", 
        details: error.message,
        notBefore: error.date
      });
    }
    
    return res.status(401).json({ 
      success: false,
      message: "Authentication failed",
      details: error.message || "Unknown error" 
    });
  }
};

// Helper functions
const validateCoordinates = (lat, lng) => {
  lat = parseFloat(lat);
  lng = parseFloat(lng);
  
  if (isNaN(lat) || isNaN(lng)) {
    return { valid: false, message: " Coordinates must be valid numbers" };
  }
  
  if (lat < -90 || lat > 90) {
    return { valid: false, message: ` Latitude value (${lat}) out of valid range (-90 to 90)` };
  }
  
  if (lng < -180 || lng > 180) {
    return { valid: false, message: ` Longitude value (${lng}) out of valid range (-180 to 180)` };
  }
  
  return { valid: true, lat, lng };
};

const extractCoordinates = (body) => {
  // Case 1: Direct latitude/longitude fields
  if (body.latitude && body.longitude) {
    return validateCoordinates(body.latitude, body.longitude);
  } 
  // Case 2: Location object
  else if (body.location) {
    try {
      let locationData;
      if (typeof body.location === 'string') {
        locationData = JSON.parse(body.location);
      } else {
        locationData = body.location;
      }
      
      if (locationData && locationData.lat !== undefined && locationData.lng !== undefined) {
        return validateCoordinates(locationData.lat, locationData.lng);
      } else {
        return { valid: false, message: " Location object missing required lat/lng properties" };
      }
    } catch (locErr) {
      return { valid: false, message: " Invalid location data format" };
    }
  } else {
    return { valid: false, message: " No location data provided - please provide latitude and longitude" };
  }
};

// Ensure map.html exists
(async function ensureMapFileExists() {
  const mapHtmlPath = path.join(__dirname, 'public', 'map.html');
  
  try {
    await fs.access(mapHtmlPath);
    // File exists, no need to create it
  } catch (error) {
    // File doesn't exist, create it
    const mapHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Property Map</title>
  <style>
    #map {
      height: 500px;
      width: 100%;
    }
    body {
      margin: 0;
      padding: 20px;
      font-family: Arial, sans-serif;
    }
    .error-message {
      color: red;
      padding: 20px;
      text-align: center;
    }
  </style>
</head>
<body>
  <h1>Property Map</h1>
  <div id="map"></div>
  <div id="error-container"></div>

  <script>
    // Initialize the map
    function initMap() {
      // Default center (can be changed to user's location)
      const defaultCenter = { lat: 20.5937, lng: 78.9629 }; // Center of India
      
      const map = new google.maps.Map(document.getElementById("map"), {
        zoom: 5,
        center: defaultCenter,
      });

      // Fetch properties from API to display on map
      fetch('/api/properties')
        .then(response => response.json())
        .then(properties => {
          if (properties.length === 0) {
            console.log('No properties found with location data');
            return;
          }
          
          properties.forEach(property => {
            if (property.latitude && property.longitude) {
              const marker = new google.maps.Marker({
                position: { lat: parseFloat(property.latitude), lng: parseFloat(property.longitude) },
                map: map,
                title: property.title
              });

              const infoWindow = new google.maps.InfoWindow({
                content: \`
                  <div>
                    <h3>\${property.title}</h3>
                    <p>\${property.address}, \${property.city}</p>
                    <p>\${property.price}</p>
                    <a href="/property/\${property.id}" target="_blank">View Details</a>
                  </div>
                \`
              });

              marker.addListener('click', () => {
                infoWindow.open(map, marker);
              });
            }
          });
        })
        .catch(error => {
          console.error('Error loading properties:', error);
          document.getElementById('error-container').innerHTML = 
            '<p class="error-message">Error loading properties. Please try again later.</p>';
        });
    }

    function handleMapError() {
      document.getElementById('map').innerHTML = 
        '<p class="error-message">Failed to load Google Maps. Please check your API key.</p>';
    }
  </script>
  <script>
    // Dynamically load the Google Maps API with the key from the server
    fetch('/api/maps/key')
      .then(response => {
        if (!response.ok) {
          throw new Error('API key not available');
        }
        return response.json();
      })
      .then(data => {
        if (!data.apiKey) {
          throw new Error('Invalid API key');
        }
        
        const script = document.createElement('script');
        script.src = \`https://maps.googleapis.com/maps/api/js?key=\${data.apiKey}&callback=initMap\`;
        script.async = true;
        script.defer = true;
        script.onerror = handleMapError;
        document.head.appendChild(script);
      })
      .catch(error => {
        console.error('Error loading Google Maps API:', error);
        handleMapError();
      });
  </script>
</body>
</html>
    `;
    
    await fs.writeFile(mapHtmlPath, mapHtml);
    console.log(" Created map.html file");
  }
})();

// Test Routes
app.get("/api/test", (req, res) => {
  res.json({ message: " Test endpoint working" });
});

app.post('/api/test-login', (req, res) => {
  res.json({ success: true, message: 'CORS test successful' });
});

app.get("/api/test-cors", (req, res) => {
  res.json({ message: "CORS is working correctly" });
});

// Maps Routes
app.get("/api/maps/key", (req, res) => {
  const apiKey = process.env.GOOGLE_MAPS_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ message: " Google Maps API key not configured" });
  }
  res.json({ apiKey });
});

app.get("/map", (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'map.html'));
});

// Signup Route
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: "All fields are required" 
      });
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid email format" 
      });
    }

    // Password strength validation
    if (password.length < 8) {
      return res.status(400).json({ 
        success: false, 
        message: "Password must be at least 8 characters long" 
      });
    }

    const connection = await pool.getConnection();
    try {
      // Check existing user
      const [existingUsers] = await connection.execute(
        "SELECT * FROM user1 WHERE email = ?", 
        [email]
      );

      if (existingUsers.length > 0) {
        connection.release();
        return res.status(409).json({ 
          success: false, 
          message: "Email already registered" 
        });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // Insert new user
      await connection.execute(
        "INSERT INTO user1 (name, email, password, is_guest) VALUES (?, ?, ?, FALSE)", 
        [name, email, hashedPassword]
      );

      connection.release();
      res.status(201).json({ 
        success: true, 
        message: "User registered successfully" 
      });

    } catch (dbError) {
      connection.release();
      handleDatabaseError(res, dbError, "Database registration error");
    }
  } catch (error) {
    handleDatabaseError(res, error);
  }
});

/// Login route with better error handling
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }
    
    // Check if user exists
    const [users] = await pool.execute(
      "SELECT id, name, email, password, is_guest, role FROM user1 WHERE email = ?", 
      [email]
    );
    
    if (users.length === 0) {
      return res.status(401).json({ error: " Invalid email or password" });
    }
    
    const user = users[0];
    
    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ error: " Invalid email or password" });
    }
    
    // Generate JWT token
    const token = jwt.sign(
      {
        id: user.id, // NEW
        userId: user.id,
        email: user.email,
        isGuest: user.is_guest || false,
        role: user.role
      }, 
      JWT_SECRET, 
      { expiresIn: "24h" }
    );
    
    
    console.log("Login successful for user:", user.email);
    
    // Return user info and token
    return res.json({
      success: true,
      message: " Login successful",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        isGuest: user.is_guest || false,
        role: user.role
      }
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ 
      error: " Server error", 
      details: process.env.NODE_ENV === 'development' ? error.message : undefined 
    });
  }
});
// Add to your Express server file
app.get("/", (req, res) => {
  res.status(200).json({ message: "Server is running" });
});


app.post("/api/guest-login", async (req, res) => {
  try {
    console.log("1. Starting guest login");
    
    // Create a unique guest ID and email
    const guestId = `guest-${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
    const guestName = "Guest User";
    const guestEmail = `${guestId}@example.com`;
    
    console.log("2. Generated guest info:", { guestName, guestEmail });
    
    // Use a simple password for testing
    const hashedPassword = "guest-password-for-testing";
    
    console.log("3. About to execute database query");
    
    // Insert the guest user - simplified for testing
    const [result] = await pool.query(
      "INSERT INTO homilet.user1 (name, email, password, is_guest, role) VALUES (?, ?, ?, TRUE, 'guest')",
      [guestName, guestEmail, hashedPassword]
    );
    
    console.log("4. Database query executed successfully, result:", result);
    
    const userId = result.insertId;
    const token = "test-token-" + Date.now(); // Simplified token for testing
    
    console.log("5. About to send success response");
    
    // Return success response
    res.status(200).json({
      success: true,
      token,
      user: {
        id: userId,
        username: guestName,
        email: guestEmail,
        isGuest: true,
        role: 'guest'
      }
    });
  } catch (error) {
    console.error("GUEST LOGIN ERROR:", error);
    res.status(500).json({ 
      success: false,
      message: "Failed to create guest session",
      error: error.message
    });
  }
});

// Middleware to check guest permissions - updated for user1 table
const restrictGuest = async (req, res, next) => {
  try {
    // Skip if not a guest user
    if (!req.user || !req.user.isGuest) {
      return next();
    }
    // Verify the guest account is still valid
    const [guests] = await pool.query(
      "SELECT id FROM homilet.user1 WHERE id = ? AND is_guest = TRUE AND guest_expiry_date > NOW()",
      [req.user.id]
    );
    
    if (guests.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Guest session expired. Please login again."
      });
    }
    
    // Check if the requested operation is allowed for guests
    const restrictedPaths = [
      '/api/profile/update',
      '/api/payment',
      '/api/admin',
    ];
    
    const allowedMethods = {
      'GET': true,  // Allow read operations
      'POST': false, // Block most write operations with exceptions below
      'PUT': false,
      'DELETE': false
    };
    
    // Exceptions - specific endpoints guests can access with POST
    const postExceptions = [
      '/api/feedback',
      '/api/search',
      '/api/register' 
    ];
    
    const path = req.path;
    const method = req.method;
    
    // Check if the path is restricted
    if (restrictedPaths.some(restrictedPath => path.startsWith(restrictedPath))) {
      return res.status(403).json({
        success: false,
        message: "This operation is not available for guest users. Please register or login."
      });
    }
    
    // Check method restrictions with exceptions
    if (!allowedMethods[method] && !(method === 'POST' && postExceptions.some(exc => path.startsWith(exc)))) {
      return res.status(403).json({
        success: false,
        message: "This operation is not available for guest users. Please register or login."
      });
    }
    
    // Update last activity time for the guest
    await pool.query(
      "UPDATE homilet.user1 SET last_activity = NOW() WHERE id = ?",
      [req.user.id]
    );
    
    next();
  } catch (error) {
    console.error("Guest restriction error:", error);
    return res.status(500).json({ 
      success: false,
      message: "Server error"
    });
  }
};

// Cleanup function for expired guest accounts - updated for user1 table
async function cleanupExpiredGuestAccounts() {
  try {
    // Get count before deletion for logging
    const [countResult] = await pool.query(
      "SELECT COUNT(*) as count FROM homilet.user1 WHERE is_guest = TRUE AND guest_expiry_date < NOW()"
    );
    // Delete expired guest accounts
    const [deleteResult] = await pool.query(
      "DELETE FROM homilet.user1 WHERE is_guest = TRUE AND guest_expiry_date < NOW()"
    );
    
    console.log(`Cleaned up ${deleteResult.affectedRows} expired guest accounts`);
    
    // Optionally log to a audit/activity table - assuming you have a system_logs table
    if (deleteResult.affectedRows > 0) {
      try {
        await pool.query(
          "INSERT INTO homilet.system_logs (action, details, created_at) VALUES (?, ?, NOW())",
          ['guest_cleanup', JSON.stringify({count: deleteResult.affectedRows})]
        );
      } catch (logError) {
        // If system_logs table doesn't exist, just log to console
        console.log("Note: Could not log to system_logs table:", logError.message);
      }
    }
  } catch (error) {
    console.error("Error cleaning up guest accounts:", error);
  }
}

// Run cleanup when server starts and then on a schedule
cleanupExpiredGuestAccounts();
const cleanupInterval = parseInt(process.env.GUEST_CLEANUP_INTERVAL || 60) * 60 * 1000;
setInterval(cleanupExpiredGuestAccounts, cleanupInterval);

console.log(`Guest account cleanup scheduled every ${cleanupInterval/60/1000} minutes`);
// Example of how to use the restrictGuest middleware with specific routes
app.use('/api/user-data', restrictGuest, (req, res) => {
  res.json({ message: "This is protected user data" });
});
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    const [users] = await pool.execute("SELECT * FROM user1 WHERE email = ?", [email]);

    if (users.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const otp = generateOTP();
    otpStore[email] = { otp, expiresAt: Date.now() + 10 * 60 * 1000 };

    const mailOptions = {
      from: "muttapavani9@gmail.com",
      to: email,
      subject: "Password Reset OTP",
      text: `Your OTP is: ${otp}. It is valid for 10 minutes.`,
    };

    await transporter.sendMail(mailOptions);
    res.json({ message: "OTP sent successfully. Check your email." });
  } catch (error) {
    handleDatabaseError(res, error, "Error sending OTP");
  }
});

// Verify OTP
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!otpStore[email]) {
    return res.status(400).json({ error: "No OTP found. Request a new OTP." });
  }

  if (Date.now() > otpStore[email].expiresAt) {
    delete otpStore[email];
    return res.status(400).json({ error: "OTP expired. Request a new one." });
  }

  if (otpStore[email].otp !== otp) {
    return res.status(400).json({ error: "Invalid OTP" });
  }

  otpStore[email].verified = true;
  res.json({ message: "OTP verified successfully." });
});

// Reset Password
app.post("/reset-password", async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({ error: "Invalid request. Missing parameters." });
    }

    if (!otpStore[email]?.verified) {
      return res.status(400).json({ error: "OTP verification required before resetting password." });
    }

    // Hash and update the password
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    
    // Update the password in MySQL
    await pool.execute("UPDATE user1 SET password = ? WHERE email = ?", [hashedPassword, email]);

    delete otpStore[email]; // Clear OTP store after successful reset
    res.json({ message: "Password reset successfully!" });

  } catch (error) {
    console.error("Password reset error:", error);
    res.status(500).json({ error: "Password reset error" });
  }
});

/// Define your user routes
app.get("/api/user", verifyToken, async (req, res) => {
  try {
    console.log("Fetching user data for ID:", req.user.id);
    
    const [users] = await pool.query(
      "SELECT id, name AS username, email, phone, address, role FROM user1 WHERE id = ?",
      [req.user.id]
    );
    
    if (users.length === 0) {
      console.log("User not found in database");
      return res.status(404).json({ message: " User not found" });
    }
    
    console.log("User data retrieved successfully");
    res.json(users[0]);
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ 
      message: " Server error",
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// User profile update route - This is the one you're trying to access
app.put("/api/user/profile", verifyToken, async (req, res) => {
  try {
    const { name, email, phone, address, role } = req.body;
    const userId = req.user.id;
    
    console.log("Update request for user ID:", userId);
    console.log("Update data:", { name, email, phone, address, role });
    
    // Validate required fields
    if (!name || !email) {
      return res.status(400).json({ message: " Name and email are required" });
    }
    
    // Verify email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: " Invalid email format" });
    }
    
    // Check if email is already in use by another account
    const [existingUsers] = await pool.query(
      "SELECT id FROM user1 WHERE email = ? AND id != ?", 
      [email, userId]
    );
    
    if (existingUsers.length > 0) {
      return res.status(409).json({ message: " Email already in use by another account" });
    }
    
    // Update the user profile
    const [result] = await pool.query(
      "UPDATE user1 SET name = ?, email = ?, phone = ?, address = ?, role = ? WHERE id = ?",
      [name, email, phone || null, address || null, role || 'tenant', userId]
    );
    
    if (result.affectedRows === 0) {
      console.log("No rows affected during update");
      return res.status(404).json({ message: " User not found" });
    }
    
    console.log("Profile updated successfully");
    
    // Return success response
    res.json({ 
      message: " Profile updated successfully",
      user: {
        id: userId,
        username: name,
        email,
        phone,
        address,
        role
      }
    });
  } catch (error) {
    console.error("Error updating user profile:", error);
    res.status(500).json({ 
      message: " Server error",
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});
// Property Routes
app.get("/api/properties", async (req, res) => {
  try {
    const [properties] = await pool.query("SELECT * FROM home_let_app_properties");
    res.json(properties);
  } catch (error) {
    console.error("Error fetching properties:", error);
    res.status(500).json({ message: " Server error" });
  }
});


app.get("/api/properties/user", verifyToken, async (req, res) => {
  try {
    const [properties] = await pool.query(
      "SELECT * FROM home_let_app_properties WHERE user_id = ?", 
      [req.user.userId]
    );
    
    res.json(properties || []);
  } catch (error) {
    console.error("Error fetching user properties:", error);
    res.status(500).json({ message: " Server error" });
  }
});

app.get("/api/properties/:id", async (req, res) => {
  try {
    const propertyId = req.params.id;
    const [properties] = await pool.query(
      "SELECT * FROM home_let_app_properties WHERE id = ?",
      [propertyId]
    );
    
    if (properties.length === 0) {
      return res.status(404).json({ message: " Property not found" });
    }
    
    res.json(properties[0]);
  } catch (error) {
    console.error("Error fetching property:", error);
    res.status(500).json({ message: " Server error" });
  }
});

app.post("/api/properties", verifyToken, upload.array("images", 5), async (req, res) => {
  try {
    // Check for images
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ message: " No images uploaded. Please upload at least one image." });
    }
    
    // Extract data from request
    const {
      title, description, propertyType, listingType, price,
      bedrooms, bathrooms, area, address, city, state, pincode,
      amenities: amenitiesJson, ownerName, ownerMobile
    } = req.body;
    
    // Validate required fields
    if (!title || !description || !price || !address || !city || !state || !pincode || !ownerName || !ownerMobile) {
      return res.status(400).json({ message: " Missing required fields" });
    }
    
    // Validate mobile number format (10 digits)
    if (!/^\d{10}$/.test(ownerMobile)) {
      return res.status(400).json({ message: " Invalid mobile number format. Please provide a 10-digit number." });
    }
    
    // Extract and validate coordinates
    const coordinates = extractCoordinates(req.body);
    if (!coordinates.valid) {
      return res.status(400).json({ message: coordinates.message });
    }
    
    // Parse amenities
    let amenities = [];
    try {
      if (amenitiesJson) {
        amenities = typeof amenitiesJson === 'string' ? JSON.parse(amenitiesJson) : amenitiesJson;
      }
    } catch (e) {
      return res.status(400).json({ message: " Invalid amenities format" });
    }
    
    // Create array of image paths
    const imagePaths = req.files.map(file => `/uploads/${file.filename}`);
    
    // Insert property data
    const [result] = await pool.query(
      `INSERT INTO home_let_app_properties (
        title, description, property_type, listing_type, price,
        bedrooms, bathrooms, area, address, city, state, pincode,
        amenities, images, latitude, longitude, user_id,
        owner_name, owner_mobile
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        title, description, propertyType, listingType, price,
        bedrooms || null, bathrooms || null, area || null,
        address, city, state, pincode,
        JSON.stringify(amenities), JSON.stringify(imagePaths), 
        coordinates.lat, coordinates.lng, req.user.userId, // Changed from req.user.id to req.user.userId
        ownerName, ownerMobile
      ]
    );
    
    res.status(201).json({
      message: " Property added successfully!",
      propertyId: result.insertId
    });
  } catch (error) {
    console.error("Error adding property:", error);
    res.status(500).json({ message: " Server error" });
  }
});

app.put("/api/properties/:id", verifyToken, async (req, res) => {
  try {
    const propertyId = req.params.id;
    const {
      title, description, propertyType, listingType, price,
      bedrooms, bathrooms, area, address, city, state, pincode,
      amenities: amenitiesJson, status, ownerName, ownerMobile
    } = req.body;
    
    // Validate required fields
    if (!title || !description || !price || !address || !city || !state || !pincode || !ownerName || !ownerMobile) {
      return res.status(400).json({ message: " Missing required fields" });
    }
    
    // Validate mobile number format (10 digits)
    if (!/^\d{10}$/.test(ownerMobile)) {
      return res.status(400).json({ message: " Invalid mobile number format. Please provide a 10-digit number." });
    }
    
    // Extract and validate coordinates
    const coordinates = extractCoordinates(req.body);
    if (!coordinates.valid) {
      return res.status(400).json({ message: coordinates.message });
    }
    
    // Parse amenities
    let amenities = [];
    try {
      if (amenitiesJson) {
        amenities = typeof amenitiesJson === 'string' ? JSON.parse(amenitiesJson) : amenitiesJson;
      }
    } catch (e) {
      return res.status(400).json({ message: " Invalid amenities format" });
    }
    
    // Verify property ownership
    const [properties] = await pool.query(
      "SELECT id FROM home_let_app_properties WHERE id = ? AND user_id = ?",
      [propertyId, req.user.id]
    );
    
    if (properties.length === 0) {
      return res.status(404).json({ message: " Property not found or unauthorized" });
    }
    
   // Update property
await pool.query(
  `UPDATE home_let_app_properties SET 
    title = ?, description = ?, property_type = ?, listing_type = ?, 
    price = ?, bedrooms = ?, bathrooms = ?, area = ?, 
    address = ?, city = ?, state = ?, pincode = ?, 
    amenities = ?, status = ?, latitude = ?, longitude = ?,
    owner_name = ?, owner_mobile = ?
  WHERE id = ? AND user_id = ?`,
  [
    title, description, propertyType, listingType,
    price, bedrooms || null, bathrooms || null, area || null,
    address, city, state, pincode,
    JSON.stringify(amenities), status || 'active',
    coordinates.lat, coordinates.lng,
    ownerName, ownerMobile,
    propertyId, req.user.userId 
  ]
);
    
    res.json({ message: " Property updated successfully" });
  } catch (error) {
    console.error("Error updating property:", error);
    res.status(500).json({ message: " Server error" });
  }
});

app.delete("/api/properties/:id", verifyToken, async (req, res) => {
  try {
    const propertyId = req.params.id;
    const connection = await pool.getConnection();
    
    try {
      await connection.beginTransaction();
      
      // Get property data
      const [properties] = await pool.query(
        "SELECT id FROM home_let_app_properties WHERE id = ? AND user_id = ?",
        [propertyId, req.user.id]
      );
      
      
      if (properties.length === 0) {
        await connection.rollback();
        return res.status(404).json({ message: " Property not found or unauthorized" });
      }
      
      // Delete property from database
      await connection.query(
        "DELETE FROM home_let_app_properties WHERE id = ? AND user_id = ?", 
        [propertyId, req.user.userId]  
      );
      await connection.commit();
      try {
        const property = properties[0];
        const imagePaths = JSON.parse(property.images || '[]');
        
        // Delete image files asynchronously
        for (const imagePath of imagePaths) {
          const localPath = path.join(__dirname, imagePath);
          try {
            await fs.access(localPath);
            await fs.unlink(localPath);
          } catch (fileErr) {
            // File might not exist, continue anyway
            console.log(`File not found or error deleting: ${localPath}`);
          }
        }
      } catch (fileErr) {
        console.error("Error during file cleanup:", fileErr);
      }
      
      res.json({ message: " Property deleted successfully" });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error("Error deleting property:", error);
    res.status(500).json({ message: " Server error" });
  }
});

app.get("/api/properties/search", async (req, res) => {
  try {
    const { 
      query, city, propertyType, listingType, minPrice, maxPrice,
      lat, lng, radius
    } = req.query;

    let sql = "SELECT * FROM home_let_app_properties WHERE 1=1";
    const params = [];

    // Add search conditions if provided
    if (query) {
      sql += " AND (title LIKE ? OR description LIKE ?)";
      params.push(`%${query}%`);
      params.push(`%${query}%`);
    }

    if (city) {
      sql += " AND city = ?";
      params.push(city);
    }

    if (propertyType) {
      sql += " AND property_type = ?";
      params.push(propertyType);
    }

    if (listingType) {
      sql += " AND listing_type = ?";
      params.push(listingType);
    }

    if (minPrice) {
      sql += " AND price >= ?";
      params.push(minPrice);
    }

    if (maxPrice) {
      sql += " AND price <= ?";
      params.push(maxPrice);
    }

    // Location-based search
    if (lat && lng && radius) {
      const latitude = parseFloat(lat);
      const longitude = parseFloat(lng);
      const searchRadius = parseFloat(radius);
      
      if (!isNaN(latitude) && !isNaN(longitude) && !isNaN(searchRadius)) {
        sql +=  ` AND (
          6371 * acos(
            cos(radians(?)) * cos(radians(latitude)) * cos(radians(longitude) - radians(?)) + 
            sin(radians(?)) * sin(radians(latitude))
          ) <= ?
        )`;
        params.push(latitude, longitude, latitude, searchRadius);
      }
    }

    // Only show active properties by default
    sql += " AND status = 'active'";

    const [properties] = await pool.query(sql, params);
    res.json(properties);
  } catch (error) {
    console.error("Error searching properties:", error);
    res.status(500).json({ message: " Server error" });
  }
});

app.get("/api/geocode", (req, res) => {
  const { address } = req.query;
  
  if (!address) {
    return res.status(400).json({ message: " Address parameter is required" });
  }
  
  const apiKey = process.env.GOOGLE_MAPS_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ message: " Google Maps API key not configured" });
  }
  
  // Return guidance for client-side geocoding
  res.json({
    status: "success",
    message: "For security reasons, use client-side geocoding with the provided API key",
    info: "The frontend should use the Google Maps JavaScript API with the Places library for geocoding"
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      message: ` Upload error: ${err.message}`
    });
  }
  
  if (err) {
    console.error("Server error:", err);
    return res.status(500).json({
      message: ` Server error: ${err.message}`
    });
  }
  
  next();
});
// Email verification function
(async function verifyEmailConfig() {
  // Check if the transporter auth credentials exist
  if (!transporter.options.auth.user || !transporter.options.auth.pass) {
    console.warn(" Email configuration missing. Email notifications will not work.");
    return;
  }
  
  try {
    await transporter.verify();
    console.log(" Email configuration verified successfully");
  } catch (error) {
    console.error(" Email configuration error:", error);
  }
})();
// // Add is_active column to properties table if it doesn't exist
(async function addIsActiveColumnIfNeeded() {
  let connection;
  try {
    connection = await pool.getConnection();
    
    // Check if column exists
    const [columns] = await connection.query(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'home_let_app_properties' 
      AND COLUMN_NAME = 'is_active'
    `);
    
    // If column doesn't exist, add it
    if (columns.length === 0) {
      await connection.query(`
        ALTER TABLE home_let_app_properties 
        ADD COLUMN is_active BOOLEAN DEFAULT TRUE
      `);
      console.log("Added is_active column to home_let_app_properties table");
    } else {
      console.log(" is_active column already exists in home_let_app_properties table");
    }
  } catch (error) {
    console.error(" Error checking/adding is_active column:", error);
  } finally {
    if (connection) connection.release();
  }
})();

// Add is_read column to contact_messages table if it doesn't exist
(async function addNotificationColumnsIfNeeded() {
  let connection;
  try {
    connection = await pool.getConnection();
    
    // Check if is_read column exists
    const [readColumns] = await connection.query(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'contact_messages' 
      AND COLUMN_NAME = 'is_read'
    `);
    
    // If is_read column doesn't exist, add it
    if (readColumns.length === 0) {
      await connection.query(`
        ALTER TABLE contact_messages 
        ADD COLUMN is_read BOOLEAN DEFAULT FALSE
      `);
      console.log(" Added is_read column to contact_messages table");
    }
    
    // Check if recipient_id column exists
    const [recipientColumns] = await connection.query(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'contact_messages' 
      AND COLUMN_NAME = 'recipient_id'
    `);
    
    // If recipient_id column doesn't exist, add it
    if (recipientColumns.length === 0) {
      await connection.query(`
        ALTER TABLE contact_messages 
        ADD COLUMN recipient_id INT
      `);
      console.log(" Added recipient_id column to contact_messages table");
    }
    
    // Check if updated_at column exists
    const [updatedColumns] = await connection.query(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'contact_messages' 
      AND COLUMN_NAME = 'updated_at'
    `);
    
    // If updated_at column doesn't exist, add it
    if (updatedColumns.length === 0) {
      await connection.query(`
        ALTER TABLE contact_messages 
        ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      `);
      console.log(" Added updated_at column to contact_messages table");
    }
    
  } catch (error) {
    console.error(" Error checking/adding notification columns to contact_messages table:", error);
  } finally {
    if (connection) connection.release();
  }
})();

app.post("/api/contact-agent", verifyToken, async (req, res) => {
  let connection;
  
  try {
    // Enhanced request logging
    console.log("Contact agent request received:", {
      userId: req.user?.id,
      propertyId: req.body.propertyId,
      messageSample: req.body.message ? `${req.body.message.substring(0, 20)}...` : undefined
    });
    
    // Check for required user authentication
    if (!req.user || !req.user.id) {
      return res.status(401).json({ 
        message: "Authentication required",
        error: "AUTH_REQUIRED"
      });
    }

    // Destructure request body
    const { 
      propertyId, 
      name, 
      email, 
      phone, 
      message 
    } = req.body;

    // Property ID validation
    if (!propertyId || isNaN(parseInt(propertyId))) {
      console.warn("Invalid propertyId in request:", {
        userId: req.user.id,
        propertyId,
        requestBody: req.body
      });
      
      return res.status(400).json({
        message: "Invalid property ID",
        error: "INVALID_PROPERTY_ID"
      });
    }

    // Validate other required fields
    const validationErrors = {};

    // Name validation
    if (!name || name.trim().length < 2) {
      validationErrors.name = "Name must be at least 2 characters";
    }

    // Email validation
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!email || !emailRegex.test(email.trim())) {
      validationErrors.email = "Valid email is required";
    }

    // Phone validation
    const cleanedPhone = phone ? phone.replace(/\D/g, '') : '';
    if (!cleanedPhone || cleanedPhone.length < 10) {
      validationErrors.phone = "Valid phone number is required";
    }

    // Message validation
    if (!message || message.trim().length < 10) {
      validationErrors.message = "Message must be at least 10 characters";
    }

    // Check for validation errors
    if (Object.keys(validationErrors).length > 0) {
      return res.status(400).json({ 
        message: "Validation failed", 
        errors: validationErrors 
      });
    }

    // Database connection with better error handling
    try {
      connection = await pool.getConnection();
      console.log("Database connection established");
    } catch (dbError) {
      console.error("Database connection error:", dbError);
      return res.status(503).json({ 
        message: "Database service unavailable", 
        error: "DB_CONNECTION_ERROR"
      });
    }

    // First, verify the contact_messages table exists before trying to use it
    try {
      const [tables] = await connection.query(`
        SELECT TABLE_NAME 
        FROM INFORMATION_SCHEMA.TABLES 
        WHERE TABLE_SCHEMA = DATABASE() 
        AND TABLE_NAME = 'contact_messages'
      `);
      
      if (tables.length === 0) {
        console.warn("contact_messages table does not exist - creating it");
        // Create the table if it doesn't exist
        await connection.query(`
          CREATE TABLE IF NOT EXISTS contact_messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            property_id INT NOT NULL,
            user_id INT NOT NULL,
            recipient_id INT,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL,
            phone VARCHAR(20) NOT NULL,
            message TEXT NOT NULL,
            status VARCHAR(20) DEFAULT 'pending',
            is_read BOOLEAN DEFAULT FALSE
          )
        `);
      }
    } catch (tableCheckError) {
      console.error("Error checking/creating contact_messages table:", tableCheckError);
      // Log but continue - we'll handle any further errors in the next steps
    }

    // Get table schema to know what columns exist
    let columnNames = [];
    try {
      const [contactMessageColumns] = await connection.query(`
        SELECT COLUMN_NAME 
        FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_SCHEMA = DATABASE() 
        AND TABLE_NAME = 'contact_messages'
      `);
      
      // Extract column names to an array for easier checking
      columnNames = contactMessageColumns.map(col => col.COLUMN_NAME.toLowerCase());
      console.log("Available columns in contact_messages table:", columnNames);
    } catch (schemaError) {
      console.error("Error fetching table schema:", schemaError);
      // Don't fail here, just assume basic columns
      columnNames = ['property_id', 'user_id', 'name', 'email', 'phone', 'message', 'created_at'];
    }

    // Implement rate limiting with better error handling
    let rateCheckPassed = true;
    let messageCount = 0;
    const MAX_MESSAGES_PER_HOUR = 5;
    
    try {
      // Determine which user ID column to use for rate limiting
      const userIdColumn = columnNames.includes('user_id') ? 'user_id' : 
                          columnNames.includes('sender_id') ? 'sender_id' : null;
      
      if (userIdColumn) {
        // Check if the table exists and has the necessary columns for rate limiting
        const checkQuery = `
          SELECT COUNT(*) as count 
          FROM contact_messages 
          WHERE ${userIdColumn} = ? 
          AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        `;
        
        const [rateLimit] = await connection.query(checkQuery, [req.user.id]);
        
        messageCount = rateLimit[0].count;
        
        if (messageCount >= MAX_MESSAGES_PER_HOUR) {
          connection.release();
          return res.status(429).json({
            message: "Rate limit exceeded. Please try again later.",
            error: "RATE_LIMIT_EXCEEDED",
            retryAfter: "1 hour"
          });
        }
        
        console.log("Rate limit check passed:", {
          userId: req.user.id,
          currentCount: messageCount,
          limit: MAX_MESSAGES_PER_HOUR
        });
      } else {
        console.warn("Could not determine user ID column for rate limiting - skipping rate limit check");
      }
    } catch (rateLimitError) {
      console.error("Error checking message rate limit:", rateLimitError);
      // Log detailed error information but continue processing
      console.error("Rate limit error details:", {
        error: rateLimitError.message,
        code: rateLimitError.code,
        stack: rateLimitError.stack
      });
      // In a production environment, you might want different behavior
      rateCheckPassed = false;
      console.log("Proceeding without rate limiting due to error");
    }

    // Property verification with better error handling
    try {
      // Check if properties table exists
      const [propertyTables] = await connection.query(`
        SELECT TABLE_NAME 
        FROM INFORMATION_SCHEMA.TABLES 
        WHERE TABLE_SCHEMA = DATABASE() 
        AND TABLE_NAME = 'home_let_app_properties'
      `);
      
      if (propertyTables.length === 0) {
        connection.release();
        return res.status(404).json({ 
          message: "Properties table not found in database",
          error: "TABLE_NOT_FOUND"
        });
      }
      
      // Check if is_active column exists in properties table
      const [columns] = await connection.query(`
        SELECT COLUMN_NAME 
        FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_SCHEMA = DATABASE() 
        AND TABLE_NAME = 'home_let_app_properties' 
        AND COLUMN_NAME = 'is_active'
      `);
      
      // Define query based on column existence
      const isActiveColumnExists = columns.length > 0;
      const propertyQuery = isActiveColumnExists 
        ? 'SELECT id, user_id, title FROM home_let_app_properties WHERE id = ? AND is_active = 1'
        : 'SELECT id, user_id, title FROM home_let_app_properties WHERE id = ?';
      
      // Execute property check query
      const [propertyCheck] = await connection.query(propertyQuery, [propertyId]);
      
      // Handle property not found
      if (propertyCheck.length === 0) {
        connection.release();
        return res.status(404).json({ 
          message: "Property not found or inactive",
          error: "PROPERTY_NOT_FOUND"
        });
      }
      
      console.log("Property verified:", {
        id: propertyCheck[0].id,
        owner: propertyCheck[0].user_id,
        title: propertyCheck[0].title
      });
      
      // Sanitize inputs for DB insertion
      const sanitizedName = name.trim();
      const sanitizedEmail = email.trim().toLowerCase();
      const sanitizedPhone = cleanedPhone;
      const sanitizedMessage = message.trim();
      
      // Prepare query and values arrays dynamically based on available columns
      let queryFields = [];
      let queryValues = [];
      let queryParams = [];
      
      // Always include property_id
      queryFields.push('property_id');
      queryValues.push('?');
      queryParams.push(propertyId);
      
      // Check for user_id or sender_id
      if (columnNames.includes('user_id')) {
        queryFields.push('user_id');
        queryValues.push('?');
        queryParams.push(req.user.id);
      } else if (columnNames.includes('sender_id')) {
        queryFields.push('sender_id');
        queryValues.push('?');
        queryParams.push(req.user.id);
      }
      
      // Add recipient_id (property owner) if the column exists
      if (columnNames.includes('recipient_id')) {
        queryFields.push('recipient_id');
        queryValues.push('?');
        queryParams.push(propertyCheck[0].user_id);
      }
      
      // Add name field
      if (columnNames.includes('name')) {
        queryFields.push('name');
        queryValues.push('?');
        queryParams.push(sanitizedName);
      } else if (columnNames.includes('sender_name')) {
        queryFields.push('sender_name');
        queryValues.push('?');
        queryParams.push(sanitizedName);
      }
      
      // Add email field
      if (columnNames.includes('email')) {
        queryFields.push('email');
        queryValues.push('?');
        queryParams.push(sanitizedEmail);
      } else if (columnNames.includes('sender_email')) {
        queryFields.push('sender_email');
        queryValues.push('?');
        queryParams.push(sanitizedEmail);
      }
      
      // Add phone field
      if (columnNames.includes('phone')) {
        queryFields.push('phone');
        queryValues.push('?');
        queryParams.push(sanitizedPhone);
      } else if (columnNames.includes('sender_phone')) {
        queryFields.push('sender_phone');
        queryValues.push('?');
        queryParams.push(sanitizedPhone);
      }
      
      // Add message field
      if (columnNames.includes('message') || columnNames.includes('message_text')) {
        const messageFieldName = columnNames.includes('message') ? 'message' : 'message_text';
        queryFields.push(messageFieldName);
        queryValues.push('?');
        queryParams.push(sanitizedMessage);
      }
      
      // Add is_read field if exists (default to false)
      if (columnNames.includes('is_read')) {
        queryFields.push('is_read');
        queryValues.push('?');
        queryParams.push(false);
      }
      
      // Add created_at field if not auto-populated
      if (columnNames.includes('created_at')) {
        queryFields.push('created_at');
        queryValues.push('NOW()');
      }
      
      // Add updated_at field if not auto-populated
      if (columnNames.includes('updated_at')) {
        queryFields.push('updated_at');
        queryValues.push('NOW()');
      }
      
      // Add status field if exists
      if (columnNames.includes('status')) {
        queryFields.push('status');
        queryValues.push('?');
        queryParams.push('pending'); // Default status
      }
      
      // Add rate_check_passed field if implementing for debugging
      if (columnNames.includes('rate_check_passed')) {
        queryFields.push('rate_check_passed');
        queryValues.push('?');
        queryParams.push(rateCheckPassed ? 1 : 0);
      }
      
      // Build the query
      const insertQuery = `
        INSERT INTO contact_messages 
        (${queryFields.join(', ')}) 
        VALUES (${queryValues.join(', ')})
      `;
      
      console.log("Executing query:", insertQuery);
      
      // Insert contact message
      const [messageResult] = await connection.query(insertQuery, queryParams);
      
      const messageId = messageResult.insertId;
      console.log("Message inserted with ID:", messageId);
      
      // Release connection
      connection.release();
      
      // Send success response
      return res.status(201).json({ 
        message: "Message sent successfully", 
        messageId: messageId
      });
      
    } catch (dbError) {
      // Handle database errors
      console.error("Database operation error:", {
        message: dbError.message,
        code: dbError.code,
        sqlState: dbError.sqlState,
        sqlMessage: dbError.sqlMessage
      });
      
      if (connection) connection.release();
      
      return res.status(500).json({ 
        message: "Database operation failed", 
        error: "DB_OPERATION_ERROR",
        details: process.env.NODE_ENV === 'development' ? dbError.message : 'Database error'
      });
    }
    
  } catch (error) {
    // General error handling
    if (connection) connection.release();

    console.error("Contact Agent Error", {
      message: error.message,
      stack: error.stack,
      userId: req.user?.id,
      propertyId: req.body?.propertyId
    });

    return res.status(500).json({ 
      message: "Unable to process your request at this time",
      error: "INTERNAL_SERVER_ERROR",
      details: process.env.NODE_ENV === 'development' ? error.message : 'Server error'
    });
  }
});

// Get all notifications for a specific property
app.get("/api/notifications/property/:propertyId", verifyToken, async (req, res) => {
  let connection;
  
  try {
    const { propertyId } = req.params;
    const userId = req.user.id;
    
    console.log("Fetching property notifications:", {
      userId,
      propertyId
    });
    
    // Check for required parameters
    if (!propertyId) {
      return res.status(400).json({ 
        message: "Property ID is required",
        error: "MISSING_PROPERTY_ID"
      });
    }
    
    // Ensure we have a valid user object
    if (!userId) {
      return res.status(401).json({ 
        message: "Authentication required",
        error: "AUTH_REQUIRED"
      });
    }
    
    connection = await pool.getConnection();
    
    // Verify the user owns this property
    const [propertyCheck] = await connection.query(
      "SELECT id FROM home_let_app_properties WHERE id = ? AND user_id = ?", 
      [propertyId, userId]
    );

    if (propertyCheck.length === 0) {
      return res.status(403).json({ 
        message: "You don't have permission to view these inquiries",
        error: "NOT_AUTHORIZED"
      });
    }
    
    // First check if contact_messages table exists
    const [tables] = await connection.query(`
      SELECT TABLE_NAME 
      FROM INFORMATION_SCHEMA.TABLES 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'contact_messages'
    `);

    if (tables.length === 0) {
      console.warn("contact_messages table does not exist");
      return res.json([]); // Return empty array instead of error
    }
    
    // Get table schema to know what columns exist
    let columnNames = [];
    try {
      const [contactMessageColumns] = await connection.query(`
        SELECT COLUMN_NAME 
        FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_SCHEMA = DATABASE() 
        AND TABLE_NAME = 'contact_messages'
      `);
      
      // Extract column names to an array for easier checking
      columnNames = contactMessageColumns.map(col => col.COLUMN_NAME.toLowerCase());
      console.log("Available columns in contact_messages table:", columnNames);
    } catch (schemaError) {
      console.error("Error fetching table schema:", schemaError);
      // Don't fail here, we'll handle this below
      columnNames = ['id', 'property_id', 'message', 'email', 'phone', 'name']; // Assume basic columns
    }
    
    // Determine sort column based on available columns
    let sortColumn = 'id'; // Default fallback sort by ID
    if (columnNames.includes('created_at')) {
      sortColumn = 'created_at';
    } else if (columnNames.includes('timestamp')) {
      sortColumn = 'timestamp';
    } else if (columnNames.includes('date_created')) {
      sortColumn = 'date_created';
    }
    
    console.log(`Using sort column: ${sortColumn}`);
    
    // Build a query that works with the available columns
    let selectColumns = [];
    
    // Always include id and property_id if they exist
    if (columnNames.includes('id')) selectColumns.push('id');
    if (columnNames.includes('property_id')) selectColumns.push('property_id');
    
    // Check for other expected columns
    const expectedColumns = ['name', 'email', 'phone', 'message', 'status', 'is_read'];
    expectedColumns.forEach(col => {
      if (columnNames.includes(col)) selectColumns.push(col);
    });
    
    // If we don't have a created_at column but need it for the frontend, add a placeholder
    if (!columnNames.includes('created_at')) {
      selectColumns.push('NOW() as created_at');
    } else {
      selectColumns.push('created_at');
    }
    
    // Ensure we have at least some columns to select
    if (selectColumns.length === 0) {
      selectColumns.push('*'); // Fallback to select all
    }
    
    const columnsStr = selectColumns.join(', ');
    
    // Build the WHERE clause safely
    let whereClause = '';
    if (columnNames.includes('property_id')) {
      whereClause = 'WHERE property_id = ?';
    } else {
      console.error("property_id column not found in contact_messages table");
      return res.json([]); // Return empty array if we can't filter properly
    }
    
    const selectQuery = `
      SELECT ${columnsStr}
      FROM contact_messages 
      ${whereClause}
      ORDER BY ${sortColumn} DESC
    `;
    
    console.log("Executing query:", selectQuery);
    
    try {
      // Get the property inquiries
      const [notifications] = await connection.query(selectQuery, [propertyId]);
      
      console.log(`Found ${notifications.length} notifications for property ${propertyId}`);
      
      // Make sure we're returning an array
      if (!Array.isArray(notifications)) {
        console.error("Query result is not an array:", notifications);
        return res.json([]);
      }
      
      connection.release();
      return res.json(notifications);
    } catch (queryError) {
      console.error("Error executing notifications query:", queryError);
      
      // Try a simpler fallback query if the complex one fails
      try {
        const [fallbackResult] = await connection.query(
          "SELECT * FROM contact_messages WHERE property_id = ?", 
          [propertyId]
        );
        
        connection.release();
        return res.json(fallbackResult || []);
      } catch (fallbackError) {
        console.error("Fallback query also failed:", fallbackError);
        connection.release();
        return res.json([]);
      }
    }
    
  } catch (error) {
    console.error("Error fetching property notifications:", error);
    if (connection) connection.release();
    
    // Return empty array instead of error to prevent frontend crashes
    return res.json([]);
  }
});
// Get all notifications for all of a user's properties
app.get("/api/notifications/property/all/:userId", verifyToken, async (req, res) => {
  let connection;
  
  try {
    const { userId } = req.params;
    
    // Check authorization
    if (parseInt(userId) !== parseInt(req.user.id)) {
      return res.status(403).json({ message: "Unauthorized access" });
    }
    
    connection = await pool.getConnection();
    
    // Get all inquiries for all properties owned by this user
    const [notifications] = await connection.query(
      `SELECT cm.*, p.title as property_title 
       FROM contact_messages cm
       JOIN home_let_app_properties p ON cm.property_id = p.id
       WHERE p.user_id = ?
       ORDER BY cm.created_at DESC`,
      [userId]
    );
    
    connection.release();
    return res.json(notifications);
    
  } catch (error) {
    console.error("Error fetching all notifications:", error);
    if (connection) connection.release();
    return res.status(500).json({ message: "Failed to fetch inquiries" });
  }
});

// Mark notifications as read
app.post("/api/notifications/mark-read", verifyToken, async (req, res) => {
  let connection;
  
  try {
    const { notificationIds } = req.body;
    
    if (!notificationIds || !Array.isArray(notificationIds) || notificationIds.length === 0) {
      return res.status(400).json({ message: "Invalid notification IDs" });
    }
    
    connection = await pool.getConnection();
    
    // Update the read status
    await connection.query(
      `UPDATE contact_messages 
       SET is_read = TRUE
       WHERE id IN (?)`,
      [notificationIds]
    );
    
    connection.release();
    return res.json({ message: "Notifications marked as read" });
    
  } catch (error) {
    console.error("Error marking notifications as read:", error);
    if (connection) connection.release();
    return res.status(500).json({ message: "Failed to update notifications" });
  }
});

// Update notification status
app.patch("/api/notifications/status/:notificationId", verifyToken, async (req, res) => {
  let connection;
  
  try {
    const { notificationId } = req.params;
    const { status } = req.body;
    
    if (!status || !['pending', 'in_progress', 'resolved', 'closed'].includes(status)) {
      return res.status(400).json({ message: "Invalid status" });
    }
    
    connection = await pool.getConnection();
    
    // First check if the user has permission to update this notification
    const [notificationCheck] = await connection.query(
      `SELECT cm.* FROM contact_messages cm
       JOIN home_let_app_properties p ON cm.property_id = p.id
       WHERE cm.id = ? AND p.user_id = ?`,
      [notificationId, req.user.id]
    );
    
    if (notificationCheck.length === 0) {
      return res.status(403).json({ message: "You don't have permission to update this inquiry" });
    }
    
    // Update the status
    await connection.query(
      `UPDATE contact_messages 
       SET status = ?, updated_at = NOW()
       WHERE id = ?`,
      [status, notificationId]
    );
    
    connection.release();
    return res.json({ message: "Notification status updated" });
    
  } catch (error) {
    console.error("Error updating notification status:", error);
    if (connection) connection.release();
    return res.status(500).json({ message: "Failed to update inquiry status" });
  }
});

// Initialize Razorpay
let razorpay;
let razorpayInitStatus = '';

// Set maximum payment amount (Razorpay's limit)
const MAX_AMOUNT_RAZORPAY = 5000000 * 100; // ₹5,000,000 in paise

try {
  const key_id = "rzp_test_Fqrbpr6LU7Ka8y"|| process.env.RAZORPAY_KEY_ID;
  const key_secret = "T49N5T2Y1bxtLpfupkFsyiDX"||process.env.RAZORPAY_KEY_SECRET;
  
  if (!key_id || !key_secret) {
    razorpayInitStatus = 'Missing credentials';
    console.warn(" Razorpay initialization failed: Missing API credentials");
  } else {
    razorpay = new Razorpay({ key_id, key_secret });
    razorpayInitStatus = 'Initialized';
    console.log(" Razorpay initialized successfully");
  }
} catch (error) {
  razorpayInitStatus = `Error: ${error.message}`;
  console.error(" Razorpay initialization error:", error.message);
}

// Cache for Razorpay test results
const razorpayTestCache = {
  lastChecked: null,
  data: null,
  ttl: 300000 // 5 minute cache
};

// Test Razorpay connection
app.get('/api/payments/test-razorpay', async (req, res) => {
  const now = Date.now();
  if (razorpayTestCache.lastChecked && (now - razorpayTestCache.lastChecked) < razorpayTestCache.ttl) {
    return res.json(razorpayTestCache.data);
  }
  
  try {
    if (!razorpay) {
      const response = { success: false, error: 'Razorpay not initialized', details: razorpayInitStatus };
      razorpayTestCache.lastChecked = now;
      razorpayTestCache.data = response;
      return res.status(500).json(response);
    }
    
    const testOrder = await razorpay.orders.create({
      amount: 100,
      currency: 'INR',
      receipt: `test_${Date.now()}`
    });
    
    const response = {
      success: true,
      message: 'Razorpay connection successful',
      testOrderId: testOrder.id,
      keyFormat: process.env.RAZORPAY_KEY_ID ? 
        `${process.env.RAZORPAY_KEY_ID.substring(0, 5)}...${process.env.RAZORPAY_KEY_ID.substring(process.env.RAZORPAY_KEY_ID.length - 4)}` : 
        'Not available'
    };
    
    razorpayTestCache.lastChecked = now;
    razorpayTestCache.data = response;
    return res.json(response);
  } catch (error) {
    const errorDetails = error.statusCode === 401 ? 'Authentication failed - invalid API keys' : error.message;
    const response = {
      success: false,
      error: 'Razorpay test failed',
      details: errorDetails,
      statusCode: error.statusCode || 500
    };
    
    razorpayTestCache.lastChecked = now;
    razorpayTestCache.data = response;
    res.status(500).json(response);
  }
});

// Check payment status
app.get('/api/payments/check-status', verifyToken, async (req, res) => {
  try {
    const { propertyId } = req.query;
    const userId = req.user.id || req.user.userId;
    
    if (!propertyId) return res.status(400).json({ success: false, message: 'Missing property ID' });

    const connection = await pool.getConnection();
    try {
      const [payments] = await connection.query(
        `SELECT * FROM home_let_app_payment_orders 
         WHERE property_id = ? AND user_id = ? AND status = 'paid'
         ORDER BY created_at DESC LIMIT 1`,
        [propertyId, userId]
      );
      
      if (payments.length === 0) {
        return res.json({ success: true, isPaid: false, paymentStatus: 'unpaid' });
      }
      
      const payment = payments[0];
      const paymentDate = new Date(payment.created_at);
      const diffDays = Math.ceil(Math.abs(new Date() - paymentDate) / (1000 * 60 * 60 * 24));
      
      if (diffDays > 30) {
        return res.json({
          success: true,
          isPaid: false,
          paymentStatus: 'expired',
          lastPaymentDate: paymentDate,
          daysSincePayment: diffDays
        });
      }
      
      return res.json({
        success: true,
        isPaid: true,
        paymentStatus: 'paid',
        paymentInfo: {
          orderId: payment.order_id,
          paymentId: payment.payment_id,
          amount: payment.amount,
          currency: payment.currency,
          date: payment.created_at,
          expiresIn: 30 - diffDays
        }
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    handleDatabaseError(res, error, 'Failed to check payment status');
  }
});
// Add these new routes to your Express app

app.post('/api/payments/create-order', verifyToken, async (req, res) => {
  console.log(`Public payment request received: Amount: ${req.body.amount}, PropertyID: ${req.body.propertyId}`);
  console.log(`User making request: ${req.user.id || req.user.userId}`);
  
  try {
    if (!razorpay) {
      console.error("Razorpay not initialized");
      return res.status(500).json({
        success: false, 
        message: 'Payment service unavailable', 
        details: razorpayInitStatus
      });
    }

    const { amount, propertyId, currency = 'INR', paymentType = 'listing', notes = '' } = req.body;
    const userId = req.user.id || req.user.userId;

    // Log incoming payment request details
    console.log(`Processing public payment: ${amount} ${currency} for property ${propertyId} by user ${userId}`);

    // Input validation with better error messages
    if (!amount) {
      return res.status(400).json({ success: false, message: 'Amount is required' });
    }
    
    const numericAmount = parseFloat(amount);
    if (isNaN(numericAmount)) {
      return res.status(400).json({ success: false, message: 'Amount must be a number' });
    }
    
    if (numericAmount <= 0) {
      return res.status(400).json({ success: false, message: 'Amount must be greater than zero' });
    }
    
    // Calculate amount in paise with safety checks
    let amountInPaise;
    try {
      const amountString = numericAmount.toFixed(2);
      amountInPaise = Math.round(parseFloat(amountString) * 100);
      console.log(`Amount in paise: ${amountInPaise}`);

      if (!Number.isSafeInteger(amountInPaise)) {
        throw new Error(`Amount in paise (${amountInPaise}) exceeds safe integer limits`);
      }
    } catch (conversionError) {
      console.error("Amount conversion error:", conversionError);
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid amount format',
        details: conversionError.message
      });
    }
    
    // Check Razorpay limits
    if (amountInPaise > MAX_AMOUNT_RAZORPAY) {
      return res.status(400).json({ 
        success: false, 
        message: `Amount exceeds maximum allowed value of ₹${(MAX_AMOUNT_RAZORPAY/100).toLocaleString()}`,
        details: 'Please enter a smaller amount or contact support for large transactions'
      });
    }
    
    if (!propertyId) {
      return res.status(400).json({ success: false, message: 'Missing required property ID' });
    }

    const connection = await pool.getConnection();
    try {
      // Property validation - only check if property exists, no ownership validation
      const [properties] = await connection.query(
        `SELECT * FROM home_let_app_properties WHERE id = ?`,
        [propertyId]
      );
      
      if (properties.length === 0) {
        return res.status(404).json({ success: false, message: 'Property not found' });
      }

      // Explicitly NOT checking ownership - any authenticated user can make payments

      // Check for existing payments
      const [payments] = await connection.query(
        `SELECT * FROM home_let_app_payment_orders 
         WHERE property_id = ? AND status = 'paid' 
         ORDER BY created_at DESC LIMIT 1`,
        [propertyId]
      );

      if (payments.length > 0) {
        const payment = payments[0];
        const diffDays = Math.ceil(Math.abs(new Date() - new Date(payment.created_at)) / (1000 * 60 * 60 * 24));
        
        if (diffDays <= 30) {
          return res.status(400).json({
            success: false,
            message: 'Property already paid for',
            paymentInfo: {
              orderId: payment.order_id,
              paymentId: payment.payment_id,
              date: payment.created_at,
              expiresIn: 30 - diffDays
            }
          });
        }
      }
    } finally {
      connection.release();
    }

    // Create the Razorpay order
    try {
      console.log("Preparing Razorpay order creation");
      
      const options = {
        amount: amountInPaise,
        currency,
        receipt: `homelet_${propertyId}_${Date.now()}`,
        notes: {
          propertyId: propertyId.toString(),
          userId: userId.toString(),
          paymentType,
          customNotes: notes
        }
      };
      
      console.log("Razorpay order options:", JSON.stringify(options));

      // Create the order with extra error handling
      let order;
      try {
        order = await razorpay.orders.create(options);
        console.log(`Order created successfully: ${order.id}`);
      } catch (rzpCreateError) {
        console.error("Razorpay order creation error:", rzpCreateError);
        
        // Handle specific Razorpay errors
        if (rzpCreateError.error && rzpCreateError.error.description) {
          return res.status(400).json({
            success: false,
            message: 'Payment gateway error',
            details: rzpCreateError.error.description
          });
        }
        
        throw rzpCreateError;
      }
      
      // Save to database
      try {
        const connection = await pool.getConnection();
        try {
          await connection.query(
            `INSERT INTO home_let_app_payment_orders 
            (order_id, property_id, user_id, amount, currency, status, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, NOW())`,
            [order.id, propertyId, userId, numericAmount, currency, 'created']
          );
          console.log(`Order ${order.id} saved to database`);
        } catch (dbError) {
          console.error("Database error saving order:", dbError);
          // Don't fail the whole transaction if DB insert fails
        } finally {
          connection.release();
        }
      } catch (dbConnectionError) {
        console.error("Database connection error:", dbConnectionError);
      }

      res.json({
        success: true,
        order,
        keyId: process.env.RAZORPAY_KEY_ID
      });
    } catch (rzpError) {
      console.error("Razorpay error:", rzpError);
      
      // Format a user-friendly error message
      let errorMessage = 'Payment processing error';
      let errorDetails = rzpError.message || 'Unknown error';
      
      if (rzpError.error) {
        if (rzpError.error.code) {
          errorDetails = `Error code: ${rzpError.error.code}. ${rzpError.error.description || errorDetails}`;
        }
        
        if (typeof rzpError.error === 'string') {
          errorDetails = rzpError.error;
        }
      }
      
      return res.status(400).json({
        success: false,
        message: errorMessage,
        details: errorDetails
      });
    }
  } catch (error) {
    console.error("General order creation error:", error);
    return res.status(500).json({
      success: false,
      message: 'Server error processing payment',
      details: error.message
    });
  }
});

app.post('/api/payments/verify-payment', verifyToken, async (req, res) => {
  console.log('Public payment verification request received');
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, paymentType = 'listing', notes = '' } = req.body;
    const userId = req.user.id || req.user.userId;
    
    // Input validation
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({
        success: false,
        message: 'Missing required verification parameters'
      });
    }

    const key_secret = process.env.RAZORPAY_KEY_SECRET;
    if (!key_secret) {
      return res.status(500).json({ 
        success: false, 
        message: 'Payment verification unavailable' 
      });
    }
    
    // Signature verification
    const hmac = crypto.createHmac('sha256', key_secret);
    hmac.update(`${razorpay_order_id}|${razorpay_payment_id}`);
    const generatedSignature = hmac.digest('hex');
    
    const isSignatureValid = generatedSignature === razorpay_signature;
    
    if (!isSignatureValid) {
      console.log('Payment signature verification failed');
      return res.status(400).json({
        success: false,
        message: 'Payment signature verification failed'
      });
    }
    
    console.log('Payment signature verified successfully');
    
    const connection = await pool.getConnection();
    try {
      // Get the payment order from database
      const [orders] = await connection.query(
        'SELECT * FROM home_let_app_payment_orders WHERE order_id = ?',
        [razorpay_order_id]
      );
      
      if (orders.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'Order not found'
        });
      }
      
      const order = orders[0];
      const propertyId = order.property_id;
      const amount = order.amount;
      const currency = order.currency;
      
      // No ownership validation - any authenticated user can verify payment
      
      // Update order status
      await connection.query(
        `UPDATE home_let_app_payment_orders 
         SET status = 'paid', payment_id = ?, verified_at = NOW(), updated_at = NOW() 
         WHERE order_id = ?`,
        [razorpay_payment_id, razorpay_order_id]
      );
      
      // Update property status if needed
      if (paymentType === 'listing') {
        await connection.query(
          `UPDATE home_let_app_properties 
           SET payment_status = 'paid', updated_at = NOW()
           WHERE id = ?`,
          [propertyId]
        );
      }
      
      // Record payment in transactions table if one exists
      try {
        await connection.query(
          `INSERT INTO home_let_app_transactions
           (user_id, property_id, payment_id, order_id, amount, status, created_at, type, notes)
           VALUES (?, ?, ?, ?, ?, 'completed', NOW(), ?, ?)`,
          [userId, propertyId, razorpay_payment_id, razorpay_order_id, amount, 
           paymentType, notes || 'Payment verified successfully']
        );
      } catch (err) {
        console.log('Could not record transaction, table might not exist:', err);
        // This shouldn't fail the verification if the table doesn't exist
      }
      
      res.json({
        success: true,
        message: 'Payment verified successfully',
        paymentInfo: {
          propertyId,
          amount,
          currency,
          orderId: razorpay_order_id,
          paymentId: razorpay_payment_id
        }
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Payment verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during payment verification',
      details: error.message
    });
  }
});

// Get payment history
app.get('/api/payments/history', verifyToken, async (req, res) => {
  let connection;
  try {
    const userId = req.user.id || req.user.userId;
    
    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID missing in token' });
    }
    
    connection = await pool.getConnection();
    
    const query = `
      SELECT 
        ph.*, 
        po.status, 
        p.title as property_title, 
        p.address as property_address,
        p.city as property_city,
        p.images as property_images
      FROM home_let_app_payment_history ph
      LEFT JOIN home_let_app_payment_orders po ON ph.order_id = po.order_id
      LEFT JOIN home_let_app_properties p ON ph.property_id = p.id
      WHERE ph.user_id = ?
      ORDER BY ph.created_at DESC
      LIMIT 100
    `;
    
    const [history] = await connection.query(query, [userId]);
    
    const processedHistory = history.map(record => {
      if (record.property_images) {
        try {
          const images = typeof record.property_images === 'string' 
            ? JSON.parse(record.property_images) 
            : record.property_images;
          record.property_thumbnail = images && images.length > 0 ? images[0] : null;
        } catch (e) {
          record.property_thumbnail = null;
        }
      }
      return record;
    });
    
    return res.json({ success: true, history: processedHistory });
  } catch (error) {
    handleDatabaseError(res, error, 'Error fetching payment history');
  } finally {
    if (connection) connection.release();
  }
});

// Get property payments
app.get('/api/payments/property/:propertyId', verifyToken, async (req, res) => {
  let connection;
  try {
    const { propertyId } = req.params;
    const userId = req.user.id || req.user.userId;
    
    if (!propertyId) {
      return res.status(400).json({ success: false, message: 'Missing property ID' });
    }
    
    connection = await pool.getConnection();
    
    const [properties] = await connection.query(
      `SELECT user_id FROM home_let_app_properties WHERE id = ?`,
      [propertyId]
    );
    console.log('Fetched property:', properties[0]);

    
    if (properties.length === 0) {
      return res.status(404).json({ success: false, message: 'Property not found' });
    }
    
    const isOwner = properties[0].user_id == userId;
    
    let query, params;
    
    if (isOwner) {
      query = `
        SELECT 
          ph.*,
          u.name as user_name,
          u.email as user_email
        FROM home_let_app_payment_history ph
        LEFT JOIN user1 u ON ph.user_id = u.id
        WHERE ph.property_id = ?
        ORDER BY ph.created_at DESC
      `;
      params = [propertyId];
    } else {
      query = `
        SELECT ph.*
        FROM home_let_app_payment_history ph
        WHERE ph.property_id = ? AND ph.user_id = ?
        ORDER BY ph.created_at DESC
      `;
      params = [propertyId, userId];
    }
    
    const [payments] = await connection.query(query, params);
    
    res.json({ success: true, isOwner, payments });
  } catch (error) {
    handleDatabaseError(res, error, 'Error fetching property payments');
  } finally {
    if (connection) connection.release();
  }
});
// Test database connection
app.get('/api/payments/test-db', async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [result] = await connection.query('SELECT 1 as test');
    res.json({ success: true, message: 'Database connection successful', result: result[0] });
  } catch (error) {
    handleDatabaseError(res, error, 'Database test failed');
  } finally {
    if (connection) connection.release();
  }
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(` Server running on port ${PORT}`);
  console.log(` Access the app at http://localhost:${PORT}`);
});
// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Closing database connection...'); 
  await pool.end();
  process.exit(0);
});