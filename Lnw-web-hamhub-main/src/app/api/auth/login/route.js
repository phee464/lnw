export const runtime = "nodejs";

import { NextResponse } from "next/server";
import { connectDB } from "@/lib/db";
import User from "@/lib/model/User";
import bcrypt from "bcryptjs";
import { signToken } from "@/lib/auth/jwt";

// Input validation helper
const validateLoginInput = (email, password) => {
  const errors = [];
  
  if (!email) {
    errors.push("Email is required");
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    errors.push("Invalid email format");
  }
  
  if (!password) {
    errors.push("Password is required");
  } else if (password.length < 6) {
    errors.push("Password must be at least 6 characters");
  }
  return errors;
};

export async function POST(req) {
  try {
    // Parse request body
    const body = await req.json();
    const { email, password } = body;

    // Validate input
    const validationErrors = validateLoginInput(email, password);
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

    // Find user by email (case insensitive)
    const user = await User.findOne({ 
      email: { $regex: new RegExp(`^${email}$`, 'i') } 
    }).select('+password'); // Include password field

    if (!user) {
      return NextResponse.json(
        { 
          message: "Invalid email or password", 
          success: false 
        },
        { status: 401 }
      );
    }

    // Check if user account is active (if you have status field)
    if (user.status && user.status === 'inactive') {
      return NextResponse.json(
        { 
          message: "Account is inactive. Please contact administrator.", 
          success: false 
        },
        { status: 403 }
      );
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return NextResponse.json(
        { 
          message: "Invalid email or password", 
          success: false 
        },
        { status: 401 }
      );
    }

    // Check JWT secret
    if (!process.env.JWT_SECRET) {
      console.error("[LOGIN_ERROR] JWT_SECRET environment variable is not set");
      return NextResponse.json(
        { 
          message: "Server configuration error", 
          success: false 
        },
        { status: 500 }
      );
    }

    // Generate JWT token
    const tokenPayload = {
      id: user._id.toString(),
      email: user.email,
      username: user.username,
      role: user.role || 'user',
    };

    const token = signToken(tokenPayload);

    // Update last login time (optional)
    await User.findByIdAndUpdate(user._id, { 
      lastLogin: new Date(),
      $inc: { loginCount: 1 }
    });

    // Prepare response data
    const userData = {
      id: user._id,
      email: user.email,
      username: user.username,
      role: user.role || 'user',
      lastLogin: new Date(),
    };

    // Create response
    const response = NextResponse.json({
      message: "Login successful",
      success: true,
      token,
      user: userData,
    });

    // Set HTTP-only cookie
    response.cookies.set("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 7, // 7 days
    });

    // Set user data cookie for client-side access (without sensitive data)
    response.cookies.set("user", JSON.stringify(userData), {
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 7, // 7 days
    });

    return response;

  } catch (error) {
    console.error("[LOGIN_ERROR]", {
      message: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString(),
    });

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