import { Hono } from "npm:hono";
import { cors } from "npm:hono/cors";
import { logger } from "npm:hono/logger";
import * as kv from "./kv_store.tsx";
import { createClient } from "npm:@supabase/supabase-js@2";
import { createRemoteJWKSet, jwtVerify } from "npm:jose@5";

const app = new Hono();

// Create Supabase client
const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

// Enable logger
app.use('*', logger(console.log));

// Enable CORS for all routes and methods
app.use(
  "/*",
  cors({
    origin: "*",
    allowHeaders: ["Content-Type", "Authorization", "X-User-Token"],
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    exposeHeaders: ["Content-Length"],
    maxAge: 600,
  }),
);

// ==================== AUTH MIDDLEWARE ====================
async function getAuthenticatedUser(c: any) {
  // Prefer X-User-Token custom header (client sends user JWT here to bypass gateway validation)
  let accessToken = c.req.header("X-User-Token");
  
  // Fall back to Authorization header
  if (!accessToken) {
    const authHeader = c.req.header("Authorization");
    if (!authHeader) return null;
    accessToken = authHeader.split(" ")[1];
  }
  
  if (!accessToken) return null;

  // 1) Try Supabase JWT first
  const { data: { user }, error } = await supabase.auth.getUser(accessToken);
  if (!error && user) return user;

  // 2) Fallback: Try Clerk JWT
  try {
    const clerkJwksUrl = Deno.env.get("CLERK_JWKS_URL");
    if (!clerkJwksUrl) return null;

    const jwks = createRemoteJWKSet(new URL(clerkJwksUrl));
    const clerkIssuer = Deno.env.get("CLERK_ISSUER");
    const verifyOptions = clerkIssuer ? { issuer: clerkIssuer } : undefined;

    const { payload } = await jwtVerify(accessToken, jwks, verifyOptions as any);

    const userId = String(payload.sub || "");
    if (!userId) return null;

    const email =
      (typeof payload.email === "string" && payload.email) ||
      (typeof payload.email_address === "string" && payload.email_address) ||
      `${userId}@clerk.local`;

    const name =
      (typeof payload.name === "string" && payload.name) ||
      email.split("@")[0] ||
      "User";

    return {
      id: userId,
      email,
      user_metadata: { name },
    };
  } catch {
    return null;
  }
}

// ==================== AUTH ROUTES ====================

// Sign Up
app.post("/make-server-19914029/auth/signup", async (c) => {
  try {
    const { email, password, name } = await c.req.json();
    
    const { data, error } = await supabase.auth.admin.createUser({
      email,
      password,
      user_metadata: { name },
      // Automatically confirm the user's email since an email server hasn't been configured.
      email_confirm: true,
    });
    
    if (error) {
      console.error("Signup error:", error);
      
      // Handle specific error cases
      if (error.code === "email_exists" || error.message?.includes("already been registered")) {
        return c.json({ error: "A user with this email address has already been registered" }, 422);
      }
      
      return c.json({ error: error.message }, 400);
    }
    
    // Create initial user profile
    if (data.user) {
      await kv.set(`user_profile:${data.user.id}`, {
        userId: data.user.id,
        email: data.user.email,
        name,
        currentStreak: 0,
        longestStreak: 0,
        totalXP: 0,
        level: 1,
        lastActiveDate: null,
        achievements: [],
        completedTopics: [],
        onboardingCompleted: false, // New users haven't completed onboarding
        createdAt: new Date().toISOString(),
      });
    }
    
    return c.json({ user: data.user }, 201);
  } catch (error) {
    console.error("Signup exception:", error);
    return c.json({ error: "Internal server error during signup" }, 500);
  }
});

// Sign In
app.post("/make-server-19914029/auth/signin", async (c) => {
  try {
    const { email, password } = await c.req.json();
    
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    
    if (error) {
      console.error("Signin error:", error);
      return c.json({ error: error.message }, 401);
    }
    
    return c.json({
      user: data.user,
      session: data.session,
    });
  } catch (error) {
    console.error("Signin exception:", error);
    return c.json({ error: "Internal server error during signin" }, 500);
  }
});

// ==================== USER PROFILE ROUTES ====================

// Get User Profile
app.get("/make-server-19914029/profile", async (c) => {
  try {
    const user = await getAuthenticatedUser(c);
    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    
    let profile = await kv.get(`user_profile:${user.id}`);
    
    // If profile doesn't exist, create a default one
    if (!profile) {
      console.log(`Profile not found for user ${user.email}, creating default profile`);
      
      profile = {
        userId: user.id,
        email: user.email,
        name: user.user_metadata?.name || user.email?.split("@")[0] || "User",
        currentStreak: 0,
        longestStreak: 0,
        totalXP: 0,
        level: 1,
        lastActiveDate: null,
        achievements: [],
        completedTopics: [],
        onboardingCompleted: false, // Default to false for new profiles
        createdAt: new Date().toISOString(),
      };
      
      await kv.set(`user_profile:${user.id}`, profile);
      console.log(`Created profile for user ${user.email}`);
    }
    
    return c.json({ profile });
  } catch (error) {
    console.error("Get profile error:", error);
    return c.json({ error: "Failed to fetch profile" }, 500);
  }
});

// Update User Profile
app.put("/make-server-19914029/profile", async (c) => {
  try {
    const user = await getAuthenticatedUser(c);
    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    
    const updates = await c.req.json();
    const currentProfile = await kv.get(`user_profile:${user.id}`);
    
    if (!currentProfile) {
      return c.json({ error: "Profile not found" }, 404);
    }
    
    const updatedProfile = { ...currentProfile, ...updates };
    await kv.set(`user_profile:${user.id}`, updatedProfile);
    
    return c.json({ profile: updatedProfile });
  } catch (error) {
    console.error("Update profile error:", error);
    return c.json({ error: "Failed to update profile" }, 500);
  }
});

// ==================== PROGRESS TRACKING ROUTES ====================

// Update Streak (call daily when user completes a lesson)
app.post("/make-server-19914029/progress/streak", async (c) => {
  try {
    const user = await getAuthenticatedUser(c);
    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    
    const profile = await kv.get(`user_profile:${user.id}`);
    if (!profile) {
      return c.json({ error: "Profile not found" }, 404);
    }
    
    const today = new Date().toISOString().split("T")[0];
    const lastActive = profile.lastActiveDate;
    
    let newStreak = profile.currentStreak || 0;
    
    // Check if user already logged today
    if (lastActive === today) {
      return c.json({ profile, message: "Already logged today" });
    }
    
    // Check if streak continues (last active was yesterday)
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayStr = yesterday.toISOString().split("T")[0];
    
    if (lastActive === yesterdayStr) {
      newStreak += 1;
    } else if (!lastActive || lastActive !== today) {
      newStreak = 1; // Reset streak
    }
    
    const updatedProfile = {
      ...profile,
      currentStreak: newStreak,
      longestStreak: Math.max(newStreak, profile.longestStreak || 0),
      lastActiveDate: today,
    };
    
    await kv.set(`user_profile:${user.id}`, updatedProfile);
    
    return c.json({ profile: updatedProfile });
  } catch (error) {
    console.error("Update streak error:", error);
    return c.json({ error: "Failed to update streak" }, 500);
  }
});

// Add XP
app.post("/make-server-19914029/progress/xp", async (c) => {
  try {
    const user = await getAuthenticatedUser(c);
    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    
    const { xp } = await c.req.json();
    const profile = await kv.get(`user_profile:${user.id}`);
    
    if (!profile) {
      return c.json({ error: "Profile not found" }, 404);
    }
    
    const newTotalXP = (profile.totalXP || 0) + xp;
    const newLevel = Math.floor(newTotalXP / 500) + 1; // 500 XP per level
    
    const updatedProfile = {
      ...profile,
      totalXP: newTotalXP,
      level: newLevel,
    };
    
    await kv.set(`user_profile:${user.id}`, updatedProfile);
    
    return c.json({ profile: updatedProfile, xpAdded: xp });
  } catch (error) {
    console.error("Add XP error:", error);
    return c.json({ error: "Failed to add XP" }, 500);
  }
});

// Complete Topic
app.post("/make-server-19914029/progress/complete-topic", async (c) => {
  try {
    const user = await getAuthenticatedUser(c);
    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    
    const { topicId, difficulty, score } = await c.req.json();
    const profile = await kv.get(`user_profile:${user.id}`);
    
    if (!profile) {
      return c.json({ error: "Profile not found" }, 404);
    }
    
    const completedTopics = profile.completedTopics || [];
    const existingIndex = completedTopics.findIndex((t: any) => t.topicId === topicId);
    
    const topicCompletion = {
      topicId,
      difficulty,
      score,
      completedAt: new Date().toISOString(),
    };
    
    if (existingIndex >= 0) {
      completedTopics[existingIndex] = topicCompletion;
    } else {
      completedTopics.push(topicCompletion);
    }
    
    const updatedProfile = {
      ...profile,
      completedTopics,
    };
    
    await kv.set(`user_profile:${user.id}`, updatedProfile);
    
    return c.json({ profile: updatedProfile });
  } catch (error) {
    console.error("Complete topic error:", error);
    return c.json({ error: "Failed to complete topic" }, 500);
  }
});

// Get User Progress
app.get("/make-server-19914029/progress", async (c) => {
  try {
    const user = await getAuthenticatedUser(c);
    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    
    const profile = await kv.get(`user_profile:${user.id}`);
    if (!profile) {
      return c.json({ error: "Profile not found" }, 404);
    }
    
    return c.json({
      completedTopics: profile.completedTopics || [],
      totalXP: profile.totalXP || 0,
      level: profile.level || 1,
      currentStreak: profile.currentStreak || 0,
      longestStreak: profile.longestStreak || 0,
    });
  } catch (error) {
    console.error("Get progress error:", error);
    return c.json({ error: "Failed to fetch progress" }, 500);
  }
});

// ==================== LEADERBOARD ROUTES ====================

// Get Leaderboard
app.get("/make-server-19914029/leaderboard", async (c) => {
  try {
    const allProfiles = await kv.getByPrefix("user_profile:");
    
    const leaderboard = allProfiles
      .map((profile: any) => ({
        name: profile.name || "Anonymous",
        totalXP: profile.totalXP || 0,
        level: profile.level || 1,
        currentStreak: profile.currentStreak || 0,
      }))
      .sort((a: any, b: any) => b.totalXP - a.totalXP)
      .slice(0, 50); // Top 50
    
    return c.json({ leaderboard });
  } catch (error) {
    console.error("Get leaderboard error:", error);
    return c.json({ error: "Failed to fetch leaderboard" }, 500);
  }
});

// ==================== ADMIN ROUTES ====================

// Get admin stats
app.get("/make-server-19914029/admin/stats", async (c) => {
  try {
    const user = await getAuthenticatedUser(c);
    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    
    // Check if user is admin
    const ADMIN_EMAILS = ["24eg110d55@anurag.edu.in", "yeshwanth3979@gmail.com"];
    if (!ADMIN_EMAILS.includes(user.email || "")) {
      return c.json({ error: "Forbidden: Admin access required" }, 403);
    }
    
    // Get all users
    const { data: { users }, error: listError } = await supabase.auth.admin.listUsers();
    if (listError) {
      console.error("Error listing users:", listError);
      return c.json({ error: "Failed to list users" }, 500);
    }
    
    // Get all profiles
    const allProfiles = await kv.getByPrefix("user_profile:");
    
    // Calculate stats
    const totalUsers = users.length;
    
    // Active today (logged in today)
    const today = new Date().toISOString().split("T")[0];
    const activeToday = allProfiles.filter((p: any) => p.lastActiveDate === today).length;
    
    // Total problems solved
    const totalProblemsSolved = allProfiles.reduce((sum: number, p: any) => {
      return sum + (p.completedTopics?.length || 0);
    }, 0);
    
    // Average completion rate (average topics completed per user)
    const avgCompletion = totalUsers > 0 
      ? Math.round((totalProblemsSolved / totalUsers / 120) * 100) // 120 total topics (8 scenarios Ã— 15 topics)
      : 0;
    
    return c.json({
      totalUsers,
      activeToday,
      totalProblemsSolved,
      avgCompletion: `${avgCompletion}%`,
    });
  } catch (error) {
    console.error("Get admin stats error:", error);
    return c.json({ error: "Failed to fetch admin stats" }, 500);
  }
});

// Get all users with details
app.get("/make-server-19914029/admin/users", async (c) => {
  try {
    const user = await getAuthenticatedUser(c);
    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    
    // Check if user is admin
    const ADMIN_EMAILS = ["24eg110d55@anurag.edu.in", "yeshwanth3979@gmail.com"];
    if (!ADMIN_EMAILS.includes(user.email || "")) {
      return c.json({ error: "Forbidden: Admin access required" }, 403);
    }
    
    // Get all users from auth
    const { data: { users }, error: listError } = await supabase.auth.admin.listUsers();
    if (listError) {
      console.error("Error listing users:", listError);
      return c.json({ error: "Failed to list users" }, 500);
    }
    
    // Get all profiles
    const allProfiles = await kv.getByPrefix("user_profile:");
    
    // Combine auth and profile data
    const usersWithProfiles = users.map(authUser => {
      const profile = allProfiles.find((p: any) => p.userId === authUser.id);
      
      // Calculate last active time
      let lastActive = "Never";
      if (authUser.last_sign_in_at) {
        const lastSignIn = new Date(authUser.last_sign_in_at);
        const now = new Date();
        const diffMs = now.getTime() - lastSignIn.getTime();
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMins / 60);
        const diffDays = Math.floor(diffHours / 24);
        
        if (diffMins < 1) lastActive = "Just now";
        else if (diffMins < 60) lastActive = `${diffMins} min${diffMins > 1 ? 's' : ''} ago`;
        else if (diffHours < 24) lastActive = `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
        else lastActive = `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
      }
      
      return {
        id: authUser.id,
        name: profile?.name || authUser.user_metadata?.name || "Unknown",
        email: authUser.email || "",
        role: ADMIN_EMAILS.includes(authUser.email || "") ? "admin" : "user",
        level: profile?.level || 1,
        xp: profile?.totalXP || 0,
        streak: profile?.currentStreak || 0,
        problemsSolved: profile?.completedTopics?.length || 0,
        joinDate: authUser.created_at,
        lastActive,
        status: profile?.lastActiveDate ? "active" : "inactive",
      };
    });
    
    return c.json({ users: usersWithProfiles });
  } catch (error) {
    console.error("Get users error:", error);
    return c.json({ error: "Failed to fetch users" }, 500);
  }
});

// Delete a specific user
app.delete("/make-server-19914029/admin/users/:userId", async (c) => {
  try {
    const user = await getAuthenticatedUser(c);
    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    
    // Check if user is admin
    const ADMIN_EMAILS = ["24eg110d55@anurag.edu.in", "yeshwanth3979@gmail.com"];
    if (!ADMIN_EMAILS.includes(user.email || "")) {
      return c.json({ error: "Forbidden: Admin access required" }, 403);
    }
    
    const userIdToDelete = c.req.param("userId");
    
    // Prevent deleting admin users
    const { data: userToDelete, error: getUserError } = await supabase.auth.admin.getUserById(userIdToDelete);
    if (getUserError) {
      return c.json({ error: "User not found" }, 404);
    }
    
    if (ADMIN_EMAILS.includes(userToDelete.user?.email || "")) {
      return c.json({ error: "Cannot delete admin users" }, 403);
    }
    
    // Delete from Supabase Auth
    const { error: deleteAuthError } = await supabase.auth.admin.deleteUser(userIdToDelete);
    if (deleteAuthError) {
      console.error(`Error deleting auth user:`, deleteAuthError);
      return c.json({ error: "Failed to delete user from auth" }, 500);
    }
    
    // Delete user profile from KV store
    await kv.del(`user_profile:${userIdToDelete}`);
    
    console.log(`Deleted user: ${userToDelete.user?.email}`);
    
    return c.json({ success: true, message: "User deleted successfully" });
  } catch (error) {
    console.error("Delete user exception:", error);
    return c.json({ error: "Internal server error while deleting user" }, 500);
  }
});

// Delete all users and create fresh admin
app.post("/make-server-19914029/admin/reset-all-users", async (c) => {
  try {
    const { adminEmail, adminPassword, resetSecret } = await c.req.json();
    const expectedResetSecret = Deno.env.get("RESET_SECRET") || "";
    
    if (!adminEmail || !adminPassword) {
      return c.json({ error: "Admin email and password are required" }, 400);
    }
    
    if (!expectedResetSecret || resetSecret !== expectedResetSecret) {
      return c.json({ error: "Invalid reset secret" }, 403);
    }
    
    // Step 1: Delete all profiles from KV store
    const allProfiles = await kv.getByPrefix("user_profile:");
    let deletedProfileCount = 0;
    
    for (const profile of allProfiles) {
      try {
        await kv.del(`user_profile:${profile.userId}`);
        deletedProfileCount++;
        console.log(`Deleted profile for user: ${profile.email}`);
      } catch (err) {
        console.error(`Error deleting profile for ${profile.email}:`, err);
      }
    }
    
    // Step 2: Check if admin auth user already exists
    const { data: { users }, error: listError } = await supabase.auth.admin.listUsers();
    
    if (listError) {
      console.error("Error listing users:", listError);
      return c.json({ error: "Failed to list users" }, 500);
    }
    
    const existingAdmin = users.find(u => u.email === adminEmail);
    let adminUserId;
    
    if (existingAdmin) {
      // Update existing admin's password
      const { error: updateError } = await supabase.auth.admin.updateUserById(
        existingAdmin.id,
        { password: adminPassword }
      );
      
      if (updateError) {
        console.error("Error updating admin password:", updateError);
        return c.json({ 
          error: "Failed to update admin password", 
          details: updateError.message 
        }, 500);
      }
      
      adminUserId = existingAdmin.id;
      console.log(`Updated existing admin password: ${adminEmail}`);
    } else {
      // Create new admin user
      const { data: adminData, error: adminError } = await supabase.auth.admin.createUser({
        email: adminEmail,
        password: adminPassword,
        user_metadata: { name: "Admin" },
        email_confirm: true,
      });
      
      if (adminError) {
        console.error("Error creating admin user:", adminError);
        return c.json({ 
          error: "Failed to create admin user", 
          details: adminError.message 
        }, 500);
      }
      
      adminUserId = adminData.user?.id;
      console.log(`Created new admin user: ${adminEmail}`);
    }
    
    // Step 3: Create fresh admin profile
    if (adminUserId) {
      await kv.set(`user_profile:${adminUserId}`, {
        userId: adminUserId,
        email: adminEmail,
        name: "Admin",
        currentStreak: 0,
        longestStreak: 0,
        totalXP: 0,
        level: 1,
        lastActiveDate: null,
        achievements: [],
        completedTopics: [],
        createdAt: new Date().toISOString(),
      });
      console.log(`Created fresh admin profile: ${adminEmail}`);
    }
    
    return c.json({
      success: true,
      deletedProfileCount,
      adminCreated: !existingAdmin,
      adminUpdated: !!existingAdmin,
      adminEmail: adminEmail,
    });
  } catch (error) {
    console.error("Reset all users exception:", error);
    return c.json({ error: "Internal server error while resetting users" }, 500);
  }
});

// Delete all non-admin users
app.delete("/make-server-19914029/admin/delete-all-users", async (c) => {
  try {
    const user = await getAuthenticatedUser(c);
    if (!user) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    
    // Check if user is admin
    const ADMIN_EMAIL = "24eg110d55@anurag.edu.in";
    if (user.email !== ADMIN_EMAIL) {
      return c.json({ error: "Forbidden: Admin access required" }, 403);
    }
    
    // Get all users from Supabase Auth
    const { data: { users }, error: listError } = await supabase.auth.admin.listUsers();
    
    if (listError) {
      console.error("Error listing users:", listError);
      return c.json({ error: "Failed to list users" }, 500);
    }
    
    let deletedCount = 0;
    const errors: any[] = [];
    
    // Delete all non-admin users
    for (const authUser of users) {
      if (authUser.email !== ADMIN_EMAIL) {
        try {
          // Delete from Supabase Auth
          const { error: deleteAuthError } = await supabase.auth.admin.deleteUser(authUser.id);
          
          if (deleteAuthError) {
            console.error(`Error deleting auth user ${authUser.email}:`, deleteAuthError);
            errors.push({ email: authUser.email, error: deleteAuthError.message });
            continue;
          }
          
          // Delete user profile from KV store
          await kv.del(`user_profile:${authUser.id}`);
          
          deletedCount++;
          console.log(`Deleted user: ${authUser.email}`);
        } catch (err) {
          console.error(`Exception deleting user ${authUser.email}:`, err);
          errors.push({ email: authUser.email, error: String(err) });
        }
      }
    }
    
    return c.json({
      success: true,
      deletedCount,
      remainingUsers: users.length - deletedCount,
      errors: errors.length > 0 ? errors : undefined,
    });
  } catch (error) {
    console.error("Delete all users exception:", error);
    return c.json({ error: "Internal server error while deleting users" }, 500);
  }
});

// Health check endpoint
app.get("/make-server-19914029/health", (c) => {
  return c.json({ status: "ok" });
});

Deno.serve(app.fetch);
