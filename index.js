const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const app = express();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const nodemailer = require('nodemailer');
const { ObjectId } = require('mongodb');
const axios = require('axios');
const MongoClient = require('mongodb').MongoClient; // Import the MongoDB client
const { v4: uuidv4 } = require('uuid');
const PORT = process.env.PORT || 3002;

app.use(cors());
app.use(bodyParser.json());

const mongoURI = 'mongodb+srv://sammathewson98:&Ip1234567@combatcustomstest.2e9pejg.mongodb.net/'; // Replace with your MongoDB URI
const dbName = 'users'; // Replace with your database name

let db; // Declare a variable to hold the MongoDB client

const jwtSecretKey = '8f7e0989a3d1b71ff3e91abdd987d8e36f8f571fb3d9f6a0a39d42f8a38d2b60'; // Store the secret key in an environment variable

// Define a middleware function for JWT verification and user extraction
const authenticateUser = (req, res, next) => {
  const token = req.header('Authorization'); // Assuming the token is sent in the 'Authorization' header

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    // Verify the token using your jwtSecretKey
    const decoded = jwt.verify(token, jwtSecretKey);
    
    // If the token is valid, you can set req.user with the userId
    req.user = { userId: decoded.userId };
    
    console.log('middleware successful');
    next(); // Continue to the next middleware or route handler
  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Create account route
app.post('/api/create-account', async (req, res) => {
  const { firstName, lastName, phone, email, password } = req.body;

  try {    
    // Check if the email already exists in the 'users' collection
    const existingUser = await db.collection('users').findOne({ email });
    
    if (existingUser) {
      // If an existing user with the same email is found, return an error response
      return res.status(400).json({ message: 'Email already exists' });
    }
    // Hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10); // Use salt rounds

    // Create the new user object
    const newUser = {
      firstName,
      lastName,
      phone,
      email,
      password: hashedPassword, // Store hashed password
      orders: [],
      address: {
        street1: "",
        street2: "",
        city: "",
        state: "",
        zip: "",
        country: "",
      },
      cart: [],
      saveForLater: [],
      isAdmin: false
    };

    // Insert the new user document into MongoDB
   const result = await db.collection('users').insertOne(newUser);

    // Get the _id of the newly created user
    const userId = result.insertedId;
    const token = jwt.sign({userId: userId}, jwtSecretKey, { expiresIn: '7d'})

    res.status(201).json({ token, message: 'Account created successfully', userId: userId.toString() });
  } catch (error) {
    console.error('Error creating account:', error);
    res.status(500).json({ message: 'Error creating account' });
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find the user by email in MongoDB
    const user = await db.collection('users').findOne({ email });

    if (user) {
      // Compare the provided password with the hashed password from MongoDB
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (isPasswordValid) {
        const token = jwt.sign({userId: user._id}, jwtSecretKey, { expiresIn: '7d'})
        const userData = { id: user._id, email: user.email, firstName: user.firstName, lastName: user.lastName, orders: user.orders, address: user.address, phone: user.phone, isAdmin: user.isAdmin };

        // Respond with token
        res.json({ token, user: userData });
      } else {
        res.status(401).json({ message: 'Invalid credentials' });
      }
    } else {
      res.status(401).json({ message: 'User not found' });
    }
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ message: 'Error logging in' });
  }
});

app.use('/api/get-user-data', authenticateUser);

// Get User Data route
app.get('/api/get-user-data/:userId', async (req, res) => {
  const userID = req.params.userId;
  console.log(`Received userId: ${userID}`);

  try {
    // Convert userID to ObjectId
    const userIdObj = new ObjectId(userID);
    console.log(`Converted userID: ${userIdObj}`);

    // Find the user by user ID in MongoDB
    const user = await db.collection('users').findOne({ _id: userIdObj });

    if (user) {
      // Return the user data
      const userData = {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        orders: user.orders,
        services: user.services,
        address: user.address,
        phone: user.phone,
        isAdmin: user.isAdmin,
      };

      res.json({ user: userData });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    console.error('Error getting user data:', error);
    res.status(500).json({ message: 'Error getting user data' });
  }
});

app.use('/api/update-account', authenticateUser);

// Update Account Route
app.post('/api/update-account', async (req, res) => {
  const { _id, firstName, lastName, phone, email, password, address } = req.body;

  try {
    // Hash the new password using bcrypt if provided
    let hashedPassword = null;
    if (password) {
      hashedPassword = await bcrypt.hash(password, 10); // Use salt rounds
    }

    // Construct the update object based on the provided fields
    const updateObject = {
      $set: {
        firstName,
        lastName,
        phone,
        email,
        address,
        // Only update the password if a new one is provided
        ...(hashedPassword && { password: hashedPassword }),
      },
    };
    // Update the user document in MongoDB based on a unique identifier (e.g., user ID)
    await db.collection('users').updateOne(
      { /* Add your unique identifier here, like user ID or email */ },
      updateObject
    );

    res.status(200).json({ message: 'Account updated successfully' });
  } catch (error) {
    console.error('Error updating account:', error);
    res.status(500).json({ message: 'Error updating account' });
  }
});

app.use('/api/update-password', authenticateUser);

// Update Password Route
app.post('/api/update-password', async (req, res) => {
  const { password } = req.body;

  const updateID = new ObjectId(req.user.userId); // Access the user's ID from req.user
  //const updateID = new ObjectId(_id);

  try {
    // Hash the new password using bcrypt if provided
    let hashedPassword = null;
    if (password) {
      hashedPassword = await bcrypt.hash(password, 10); // Use salt rounds
    }

    // Construct the update object based on the provided fields
    const updateObject = {
      $set: {
        // Only update the password if a new one is provided
        ...(hashedPassword && { password: hashedPassword }),
      },
    };

    console.log(updateObject);
    // Update the user document in MongoDB based on a unique identifier (e.g., user ID)
    await db.collection('users').updateOne(
      { _id: updateID }, // Use the user's unique ID here
      updateObject
    );

    res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Error updating password:', error);
    res.status(500).json({ message: 'Error updating password' });
  }
});

app.use('/api/post-cart', authenticateUser);

app.post('/api/post-cart', async (req, res) => {
  const { _id, items } = req.body;
  const userIdObj = new ObjectId(_id);
  const user = await db.collection('users').findOne({ _id: userIdObj });
  
  try {
  if (user) {
    const userCart = items;
    
    // Update the user's JSON object in the "users" collection
    await db.collection('users').updateOne(
      { _id: userIdObj }, 
      { $set: { cart: userCart } }// set the cart equal to the user's current cart
    );
  } else {
    res.status(404).json({ message: 'User not found' });
  } 
} catch (error) {
  console.error('Error getting updating cart:', error);
  res.status(500).json({ message: 'Error updating cart' });
}
});

app.use('/api/get-cart-data', authenticateUser);

// Get Cart Data route
app.get('/api/get-cart-data/:userId', async (req, res) => {
  const _id = req.params.userId;
  console.log(`Received userId: ${_id}`);

  try {
    // Convert userID to ObjectId
    const userIdObj = new ObjectId(_id);
    console.log(`Converted userID: ${userIdObj}`);

    // Find the user by user ID in MongoDB
    const user = await db.collection('users').findOne({ _id: userIdObj });

    if (user) {
      // Return the user data
      const userData = {
        id: user._id,
        cartData: user.cart
      };

      res.json({ user: userData });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    console.error('Error getting user data:', error);
    res.status(500).json({ message: 'Error getting cart data' });
  }
});

// Create order route
app.post('/api/post-order', async (req, res) => {
  const { _id, firstName, lastName, phone, email, address, orderContent, hasAccount } = req.body;

  try {
    const orderID = uuidv4();
    // Create the new order object
    const newOrder = {
      orderID,
      firstName,
      lastName,
      phone,
      email,
      orderContent,
      address,
      hasAccount,
      date: new Date()
    };

    const userIdObj = new ObjectId(_id);

    // Insert the new order document into MongoDB
    await db.collection('orders').insertOne(newOrder);
    
    // Update the user's JSON object in the "users" collection
    await db.collection('users').updateOne(
      { _id: userIdObj }, 
      { $push: { orders: {
        orderID: orderID,
        date: new Date(),
        order: orderContent,
      } } }// Add the new order to the user's orders array
    );

    res.status(201).json({ message: 'Order posted successfully' });
  } catch (error) {
    console.error('Error posting order:', error);
    res.status(500).json({ message: 'Error posting order' });
  }
});

app.post('/api/save-service', async (req, res) => {
  try {
    const { _id, name, priceRange, richTextContent, deleteService } = req.body;
    const serviceId = req.body.serviceUpdate._id;

    const serviceObj = {
      _id: req.body.serviceUpdate._id,
      name: req.body.serviceUpdate.name,
      priceRange: req.body.serviceUpdate.priceRange,
      richTextContent: req.body.serviceUpdate.richTextContent,
      deleteServiceFlag: req.body.serviceUpdate.deleteService
    }

    const existingService = await db.collection('services').findOne({ _id: serviceId });

    if (serviceObj.deleteServiceFlag === true) {
      // Delete existing service
      if (existingService) {
        await db.collection('services').deleteOne({ _id: serviceId });
        res.status(200).json({ message: 'Service deleted successfully' });
      } else {
        res.status(404).json({ message: 'Service not found for deletion' });
      }
    } else if (existingService) {
      // Update existing service
      await db.collection('services').updateOne(
        { _id: serviceId },
        {
          $set: {
            name: serviceObj.name,
            priceRange: serviceObj.priceRange,
            richTextContent: serviceObj.richTextContent,
          },
        }
      );
      res.status(200).json({ message: 'Service update posted successfully' });
    } else {
      // Create a new service
      const serviceID = uuidv4();
      const newService = {
        _id: serviceID,
        name: serviceObj.name,
        priceRange: serviceObj.priceRange,
        richTextContent: serviceObj.richTextContent,
      };

      console.log(newService);
      await db.collection('services').insertOne(newService);
      res.status(201).json({ message: 'Service created successfully' });
    }
  } catch (error) {
    console.error('Error posting update:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// Get Service route
app.get('/api/services', async (req, res) => {
  try {
    const servicesCursor = db.collection('services').find(); // Retrieve all services from MongoDB

    // Convert the cursor to an array of documents
    const services = await servicesCursor.toArray();
    res.json(services); // Send the services as JSON
  } catch (error) {
    console.error('Error retrieving services:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Get All Orders route
app.get('/api/get-orders', async (req, res) => {
  try {
    const ordersCursor = db.collection('orders').find(); // Retrieve all services from MongoDB

    // Convert the cursor to an array of documents
    const orders = await ordersCursor.toArray();

    res.json(orders); // Send the services as JSON
  } catch (error) {
    console.error('Error retrieving orders:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Create review route
app.post('/api/post-review', async (req, res) => {
  const { _id, name, text } = req.body;

  try {
    const reviewID = uuidv4();
    // Create the new order object
    const newReview = {
      reviewID,
      name,
      text,
      reviewDate: new Date()
    };

    console.log(_id, newReview);

    const serviceId = _id;
    
    // Update the service's JSON object in the "services" collection
    await db.collection('services').updateOne(
      { _id: serviceId }, 
      { $push: { reviews: {
        reviewID: newReview.reviewID,
        date: newReview.reviewDate,
        name: newReview.name,
        text: newReview.text,
      } } }// Add the review to the service's review array
    );

    res.status(201).json({ message: 'Review posted successfully' });
  } catch (error) {
    console.error('Error posting review:', error);
    res.status(500).json({ message: 'Error posting reviewe' });
  }
});

// Create service request route
app.post('/api/service-request', async (req, res) => {
  const { name, email, phone, description, hasAccount, requestedService } = req.body;

  try {
    // Create the new order object
    const newRequest = {
      name: req.body.formData.name,
      email: req.body.formData.email,
      phone: req.body.formData.phone,
      description: req.body.formData.description,
      hasAccount: req.body.formData.hasAccount,
      requestedService: req.body.formData.requestedService,
      requestDate: new Date()
    };
    
    console.log(newRequest);

    // Update the service's JSON object in the "requested-services" collection
    const result = await db.collection('requested-services').insertOne(newRequest);

    if (newRequest.hasAccount) {
      const userResult = await db.collection('users').updateOne(
      { email: newRequest.email }, // Use the user's email to identify them
      {
        $push: {
          services: {
            serviceID: newRequest.requestedService,
            date: newRequest.requestDate,
            description: newRequest.description,
          },
        },
      }
    );
    console.log(userResult);
    };

    const requestedServiceID = result.insertedId;

    res.status(201).json({ message: 'Request posted successfully', requestedServiceID: requestedServiceID.toString() });
  } catch (error) {
    console.error('Error posting request:', error);
    res.status(500).json({ message: 'Error posting request' });
  }
});

// Get All Requested Services route
app.get('/api/get-requested-services', async (req, res) => {
  try {
    const servicesCursor = db.collection('requested-services').find(); // Retrieve all services from MongoDB

    // Convert the cursor to an array of documents
    const requestedServices = await servicesCursor.toArray();

    res.json(requestedServices); // Send the services as JSON
  } catch (error) {
    console.error('Error retrieving requested services:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Forgot Password Email
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
      user: 'sammathewson98@gmail.com', // Replace with your Gmail address
      pass: 'ygywixgnuunlerwr', // Replace with your Gmail password or app-specific password
    },
    tls: {
      rejectUnauthorized: false,
    },
  });

  console.log(req.body);

  // Check if the email exists in the database
  const user = await db.collection('users').findOne({ email: email });

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  // Generate a JWT token with the user's email and send it in the email
  const token = jwt.sign({userId: user._id}, jwtSecretKey, { expiresIn: '7d'})

  // Send the password reset link in the email
  const resetLink = `http://localhost:3000/ResetPassword?token=${token}`;

  const mailOptions = {
    from: 'sammathewson98@gmail.com',
    to: email, // Replace with the recipient's email address
    subject: 'Combat Customs Forgotten Password',
    text: `Click the following link to reset your password: ${resetLink}`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Email sent successfully');
    res.sendStatus(200);
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).send('Error sending email');
  }
});


(async () => {
  try {
    // Initialize the MongoDB client
    const client = await MongoClient.connect(mongoURI, { useNewUrlParser: true });
    db = client.db(dbName);

    console.log('MongoDB connected successfully');

    // Start the Express server after the MongoDB connection is established
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
  }
})();

// Send email for Contact Us form

app.post('/send-email', async (req, res) => {
  const { name, email, phone, description } = req.body;

  const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
      user: 'sammathewson98@gmail.com', // Replace with your Gmail address
      pass: 'ygywixgnuunlerwr', // Replace with your Gmail password or app-specific password
    },
    tls: {
      rejectUnauthorized: false,
    },
  });

  const mailOptions = {
    from: 'sammathewson98@gmail.com',
    to: 'sammathewson98@mail.com', // Replace with the recipient's email address
    subject: 'New Contact Form Submission',
    text: `
      Name: ${name}
      Email: ${email}
      Phone: ${phone}
      Description: ${description}
    `,
  };
});

  // Create account email
  app.post('/new-account-email', async (req, res) => {
    const { firstName, email, phone } = req.body;
  
    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: 'sammathewson98@gmail.com', // Replace with your Gmail address
        pass: 'ygywixgnuunlerwr', // Replace with your Gmail password or app-specific password
      },
      tls: {
        rejectUnauthorized: false,
      },
    });
  
    const mailOptions = {
      from: 'sammathewson98@gmail.com',
      to: email,
      subject: 'Your new account with Combat Customs',
      text: `
        Dear ${firstName},

        Thanks for creating an account with Combat Customs TX! We greatly value your business, and are excited to provide you the best of service.

        Make sure to visit your user profile to update your address and contact information, and opt in to text messaging and emails so that you can be eligible for the latest and greatest information, deals and giveaways that Combat Customs has to offer.

        If you have any questions or need further assistance, please feel free to contact us.

        Email: thamid@combatcustomstx.com
        Phone: 1234567890
  
        Sincerely,
        Combat Customs TX
      `,
    };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Email sent successfully');
    res.sendStatus(200);
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).send('Error sending email');
  }
});

// Send email for Service Request form
app.post('/send-service-request', async (req, res) => {
  const { name, email, phone, description, hasAccount, requestedService } = req.body;

  const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
      user: 'sammathewson98@gmail.com', // Replace with your Gmail address
      pass: 'ygywixgnuunlerwr', // Replace with your Gmail password or app-specific password
    },
    tls: {
      rejectUnauthorized: false,
    },
  });

  const defaultRecipientEmail = 'sammathewson98@mail.com'; // Replace with the default recipient's email address

  // Email to the default recipient
  const defaultMailOptions = {
    from: defaultRecipientEmail,
    to: defaultRecipientEmail,
    subject: 'Combat Customs Service Request Confirmation',
    text: `
      Name: ${name}
      Email: ${email}
      Phone: ${phone}
      User has account: ${hasAccount}
      Description: ${description}
      Service Requested: ${requestedService}
    `,
  };

  // Email to the user who requested the service
  const userMailOptions = {
    from: defaultRecipientEmail, // Replace with your app's email address
    to: email, // Use the user's email here
    subject: 'Combat Customs Service Request Confirmation',
    text: `
      Dear ${name},

      Thank you for choosing Combat Customs! We greatly value your business, and are excited to provide you the best of service.
      
      We have received your request and will get back to you shortly with an invoice for your service and instructions for next steps.

      Your confirmation number is XYZ. Below is some information about the service you requested.

      Service Requested: ${requestedService}
      Description: ${description}
      
      If you have any questions or need further assistance, please feel free to contact us.

      Email: thamid@combatcustomstx.com
      Phone: 1234567890

      Sincerely,
      Combat Customs TX
    `,
  };

  try {
    // Send email to the default recipient
    await transporter.sendMail(defaultMailOptions);
    
    // Send email to the user who requested the service
    await transporter.sendMail(userMailOptions);

    console.log('Emails sent successfully');
    res.sendStatus(200);
  } catch (error) {
    console.error('Error sending emails:', error);
    res.status(500).send('Error sending emails');
  }
});


app.get('/api/contentful/firearms', async (req, res) => {
  const spaceId = '1amfsf5jgvpd';
  const contentTypeId = 'combatCustomsFirearms';
  const environment = 'master';
  const accessToken = '5Rl6P7Ns3rKdF2SwZZGqadMO3_ZCIYvVkj5E4S-Lawo';

  const url = `https://cdn.contentful.com/spaces/${spaceId}/environments/${environment}/entries?content_type=${contentTypeId}&access_token=${accessToken}`;

  try {
    const response = await axios.get(url);
    res.json(response.data.items);
  } catch (error) {
    console.error('Error fetching data from Contentful:', error.message);
    res.status(500).json({ error: 'An error occurred' });
  }
});

app.get('/api/contentful/gallery', async (req, res) => {
  const spaceId = '1amfsf5jgvpd';
  const contentTypeId = 'combatCustomsGallery';
  const environment = 'master';
  const accessToken = '5Rl6P7Ns3rKdF2SwZZGqadMO3_ZCIYvVkj5E4S-Lawo';

  const url = `https://cdn.contentful.com/spaces/${spaceId}/environments/${environment}/entries?content_type=${contentTypeId}&access_token=${accessToken}`;

  try {
    const response = await axios.get(url);
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching data from Contentful:', error.message);
    res.status(500).json({ error: 'An error occurred' });
  }
});

app.get('/api/contentful/featured', async (req, res) => {
  const spaceId = '1amfsf5jgvpd';
  const contentTypeId = 'combatCustomsFeatured';
  const environment = 'master';
  const accessToken = '5Rl6P7Ns3rKdF2SwZZGqadMO3_ZCIYvVkj5E4S-Lawo';

  const url = `https://cdn.contentful.com/spaces/${spaceId}/environments/${environment}/entries?content_type=${contentTypeId}&access_token=${accessToken}`;

  try {
    const response = await axios.get(url);
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching data from Contentful:', error.message);
    res.status(500).json({ error: 'An error occurred' });
  }
});

app.post('/api/contentful/firearms-review/:itemId', async (req, res) => {
  const spaceId = '1amfsf5jgvpd';
  const contentTypeId = 'combatCustomsFirearms';
  const environment = 'master';
  const accessToken = '5Rl6P7Ns3rKdF2SwZZGqadMO3_ZCIYvVkj5E4S-Lawo';

  try {
    const itemId = req.params.itemId;
    const reviewData = req.body; // Assuming your review data is sent as JSON

    // Construct the URL for posting a review to Contentful
    const contentfulUrl = `https://api.contentful.com/spaces/${spaceId}/environments/${environment}/entries/${itemId}/reviews`;

    // Add the necessary query parameters for Contentful
    const queryParams = {
      content_type: contentTypeId,
      access_token: accessToken
    };

    // Make a POST request to Contentful with Axios
    const response = await axios.post(contentfulUrl, {
      fields: {
        // Define the fields for your review entry as needed
        // For example, if you have a 'reviewText' field in Contentful
        reviews: {
          'en-US': reviewData.review, // Assuming 'en-US' locale
        },
      },
    }, {
      params: queryParams,
    });

    // Handle the response from Contentful as needed
    res.status(response.status).json(response.data);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

app.get('/api/contentful/services', async (req, res) => {
  const spaceId = '1amfsf5jgvpd';
  const contentTypeId = 'combatCustomsServices';
  const environment = 'master';
  const accessToken = '5Rl6P7Ns3rKdF2SwZZGqadMO3_ZCIYvVkj5E4S-Lawo';

  const url = `https://cdn.contentful.com/spaces/${spaceId}/environments/${environment}/entries?content_type=${contentTypeId}&access_token=${accessToken}`;

  try {
    const response = await axios.get(url);
    res.json(response.data.items);
  } catch (error) {
    console.error('Error fetching data from Contentful:', error.message);
    res.status(500).json({ error: 'An error occurred' });
  }
});

app.get('/api/contentful/accessories', async (req, res) => {
  const spaceId = '1amfsf5jgvpd';
  const contentTypeId = 'combatCustomsAccessories';
  const environment = 'master';
  const accessToken = '5Rl6P7Ns3rKdF2SwZZGqadMO3_ZCIYvVkj5E4S-Lawo';

  const url = `https://cdn.contentful.com/spaces/${spaceId}/environments/${environment}/entries?content_type=${contentTypeId}&access_token=${accessToken}`;

  try {
    const response = await axios.get(url);
    res.json(response.data.items);
  } catch (error) {
    console.error('Error fetching data from Contentful:', error.message);
    res.status(500).json({ error: 'An error occurred' });
  }
});

app.get('/api/contentful/parts', async (req, res) => {
  const spaceId = '1amfsf5jgvpd';
  const contentTypeId = 'combatCustomsParts';
  const environment = 'master';
  const accessToken = '5Rl6P7Ns3rKdF2SwZZGqadMO3_ZCIYvVkj5E4S-Lawo';

  const url = `https://cdn.contentful.com/spaces/${spaceId}/environments/${environment}/entries?content_type=${contentTypeId}&access_token=${accessToken}`;

  try {
    const response = await axios.get(url);
    res.json(response.data.items);
  } catch (error) {
    console.error('Error fetching data from Contentful:', error.message);
    res.status(500).json({ error: 'An error occurred' });
  }
});