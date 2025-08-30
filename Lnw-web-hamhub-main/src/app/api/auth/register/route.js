export const runtime = "nodejs";

import { NextResponse } from "next/server";
import { connectDB } from "@/lib/db";
import User from "@/lib/model/User";
import bcrypt from "bcryptjs";
import { signToken } from "@/lib/auth/jwt";

// Input validation helper
const validateRegisterInput = (username, email, password, confirmPassword) => {
  const errors = [];
  
  // Username validation
  if (!username) {
    errors.push("Username is required");
  } else if (username.length < 3) {
    errors.push("Username must be at least 3 characters long");
  } else if (username.length > 20) {
    errors.push("Username must not exceed 20 characters");
  } else if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    errors.push("Username can only contain letters, numbers, and underscores");
  }
  
  // Email validation
  if (!email) {
    errors.push("Email is required");
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    errors.push("Invalid email format");
  }
  
  // Password validation
  if (!password) {
    errors.push("Password is required");
  } else {
    if (password.length < 8) {
      errors.push("Password must be at least 8 characters long");
    }
    if (!/(?=.*[a-z])/.test(password)) {
      errors.push("Password must contain at least one lowercase letter");
    }
    if (!/(?=.*[A-Z])/.test(password)) {
      errors.push("Password must contain at least one uppercase letter");
    }
    if (!/(?=.*\d)/.test(password)) {
      errors.push("Password must contain at least one number");
    }
    if (!/(?=.*[@$!%*?&])/.test(password)) {
      errors.push("Password must contain at least one special character (@$!%*?&)");
    }
  }
  
  // Confirm password validation
  if (confirmPassword && password !== confirmPassword) {
    errors.push("Password confirmation does not match");
  }
  
  return errors;
};

export async function POST(req) {
  try {
    // Parse request body
    const body = await req.json();
    const { username, email, password, confirmPassword, firstName, lastName } = body;

    // Validate input
    const validationErrors = validateRegisterInput(username, email, password, confirmPassword);
    if (validationErrors.length > 0) {
      return NextResponse.json(
        { 
          message: "Validation failed", 
          errors: validationErrors,
          success: false 
        },
        { status: 400 }
      );
    }

    // Connect to database
    await connectDB();

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [
        { email: { $regex: new RegExp(`^${email}$`, 'i') } },
        { username: { $regex: new RegExp(`^${username}$`, 'i') } }
      ]
    });

    if (existingUser) {
      const field = existingUser.email.toLowerCase() === email.toLowerCase() ? 'email' : 'username';
      return NextResponse.json(
        { 
          message: `User with this ${field} already exists`,
          success: false,
          field
        },
        { status: 409 }
      );
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Prepare user data
    const userData = {
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      password: hashedPassword,
      role: 'user', // Default role
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
      loginCount: 0,
    };

    // Add optional fields if provided
    if (firstName) userData.firstName = firstName;
    if (lastName) userData.lastName = lastName;

    // Create user
    const newUser = await User.create(userData);

    // Generate JWT token for automatic login
    const tokenPayload = {
      id: newUser._id.toString(),
      email: newUser.email,
      username: newUser.username,
      role: newUser.role,
    };

    const token = signToken(tokenPayload);

    // Prepare response user data (exclude sensitive information)
    const responseUser = {
      id: newUser._id,
      username: newUser.username,
      email: newUser.email,
      role: newUser.role,
      firstName: newUser.firstName,
      lastName: newUser.lastName,
      createdAt: newUser.createdAt,
    };

    // Create response
    const response = NextResponse.json(
      {
        message: "Registration successful",
        success: true,
        token,
        user: responseUser,
      },
      { status: 201 }
    );

    // Set HTTP-only cookie for automatic login
    response.cookies.set("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 7, // 7 days
    });

    // Set user data cookie for client-side access
    response.cookies.set("user", JSON.stringify(responseUser), {
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 7, // 7 days
    });

    return response;

  } catch (error) {
    console.error("[REGISTER_ERROR]", {
      message: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString(),
    });

    // Handle specific MongoDB errors
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0];
      return NextResponse.json(
        { 
          message: `User with this ${field} already exists`,
          success: false,
          field
        },
        { status: 409 }
      );
    }

    return NextResponse.json(
      { 
        message: "Internal server error", 
        success: false,
        ...(process.env.NODE_ENV === "development" && { error: error.message })
      },
      { status: 500 }
    );
  }
}

// Handle unsupported methods
export async function GET() {
  return NextResponse.json(
    { message: "Method not allowed" },
    { status: 405 }
  );
}

export async function PUT() {
  return NextResponse.json(
    { message: "Method not allowed" },
    { status: 405 }
  );
}

export async function DELETE() {
  return NextResponse.json(
    { message: "Method not allowed" },
    { status: 405 }
  );
}