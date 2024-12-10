# INSTALLATION
To install this application you need to first clone the stater project and run the command below to install all the dependencies required for the course

```bash
npm i --legacy-peer-deps
```

we are going to be making reference to some pre-written code which i will provide here for your references

## src/models/user.ts
```ts
import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

export default mongoose.models.User || mongoose.model('User', UserSchema);
```
## src/models/post.ts
```ts
import mongoose from 'mongoose';

const PostSchema = new mongoose.Schema({
    title: { type: String, required: true },
    image: { type: String, required: true },
    content: { type: String, required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now },
});

export default mongoose.models.Post || mongoose.model('Post', PostSchema);
```

## src/types/next-auth.d.ts
```ts
import 'next-auth';
import { DefaultSession } from 'next-auth';

declare module 'next-auth' {
    interface User {
        id: string;
        username: string;
    }

    interface Session {
        user: {
            id: string;
            username: string;
        } & DefaultSession['user']
    }
}

declare module 'next-auth/jwt' {
    interface JWT {
        id: string;
        username: string;
    }
}
```

## api/auth/[...nextauth]/route.ts
```ts
import NextAuth, { NextAuthOptions } from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import connectDB from '@/lib/db';
import User from '@/models/User';
import { Password } from '@/lib/password';

export const authOptions: NextAuthOptions = {
    providers: [
        CredentialsProvider({
            name: 'Credentials',
            credentials: {
                email: { label: "Email", type: "email" },
                password: { label: "Password", type: "password" }
            },
            async authorize(credentials) {
                await connectDB();

                if (!credentials?.email || !credentials.password) return null;

                const user = await User.findOne({ email: credentials.email });
                if (!user) return null;

                const isPasswordCorrect = await Password.verify(credentials.password, user.password);

                return isPasswordCorrect ? {
                    id: user._id.toString(),
                    email: user.email,
                    username: user.username
                } : null;
            }
        })
    ],
    callbacks: {
        async jwt({ token, user }) {
            if (user) {
                token.id = user.id;
                token.username = user.username;
            }
            return token;
        },
        async session({ session, token }) {
            session.user.id = token.id as string;
            session.user.username = token.username as string;
            return session;
        }
    },
    pages: {
        signIn: '/login',
        signOut: '/logout'
    },
    secret: process.env.NEXTAUTH_SECRET,
};

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };

```

## src/lib/db.ts

```ts
import mongoose from 'mongoose';

const MONGODB_URI = process.env.MONGODB_URI!;

if (!MONGODB_URI) {
    throw new Error('Please define the MONGODB_URI environment variable');
}

let cached = global.mongoose;

if (!cached) {
    cached = global.mongoose = { conn: null, promise: null };
}

async function connectDB() {
    if (cached.conn) return cached.conn;

    if (!cached.promise) {
        cached.promise = mongoose.connect(MONGODB_URI).then((mongoose) => mongoose);
    }

    cached.conn = await cached.promise;
    return cached.conn;
}

export default connectDB;
```

## Validation (src/lib/definition)
```ts
export const SignupFormSchema = z.object({
    username: z.string()
        .min(2, { message: 'Name must be at least 2 characters long.' })
        .trim(),
    email: z.string().email({ message: 'Please enter a valid email.' }).max(100),
    password: z.string().min(8, { message: 'Be at least 8 characters long' })
});

export type SignupFormState =
    | {
        errors?: {
            username?: string[]
            email?: string[]
            password?: string[]
        }
        message?: string
    }
    | undefined
```

## src/middleware
```ts
import { NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';
import type { NextRequest } from 'next/server';

export async function middleware(req: NextRequest) {
    const token = await getToken({ req, secret: process.env.NEXTAUTH_SECRET });

    if (!token) {
        return NextResponse.redirect(new URL('/login', req.url));
    }

    return NextResponse.next();
}

export const config = {
    matcher: ['/dashboard', '/posts/create'],
};
```

## axios instance
```ts
export const Axios = axios.create({
    baseURL: process.env.API_BASE_URL,
    headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
    },
    withCredentials: true
})
```

## Password class
```ts
import bcrypt from 'bcryptjs';

export class Password {
    static async hash(text: string): Promise<string> {
        const salt = await bcrypt.genSalt(10);
        return await bcrypt.hash(text, salt);
    }

    static async verify(text: string, hash: string): Promise<boolean> {
        return await bcrypt.compare(text, hash);
    }
}
```

## src/actions/post.ts
```ts

"use server"
import { Axios, CreatePostFormSchema, CreatePostFormState } from "@/lib/definitions";

export async function getPosts() {
    try {
        return (await Axios.get('/posts')).data
    } catch (error: any) {
        console.log(error);
    }
}

export async function getPostById(postId: string) {
    try {
        return (await Axios.get(`/posts/${postId}`)).data
    } catch (error: any) {
        console.log(error);
    }
}


export async function deletePost(postId: string): Promise<boolean> {
    try {
        await Axios.delete(`/posts/${postId}`)
        return true;
    } catch (error: any) {
        console.log(error.message);
    }

    return false;
}



export async function createPost(state: CreatePostFormState, formData: FormData) {
    const validatedFields = CreatePostFormSchema.safeParse({
        title: formData.get('title'),
        image: formData.get('image'),
        content: formData.get('content')
    });

    if (!validatedFields.success) {
        return { errors: validatedFields.error.flatten().fieldErrors }
    }

    if (formData.get('author') === '' || formData.get('author') === undefined) {
        return { noAuthor: true }
    }

    try {
        const res = await Axios.post('/posts', {
            ...validatedFields.data,
            author: formData.get('author')
        })

        return { success: true }
    } catch (error: any) {
        console.log(error.message);
    }
}
```

## src/lib/redux/postSlice.ts
```ts
import { createSlice, PayloadAction, createAsyncThunk } from '@reduxjs/toolkit';
import { getPosts, getPostById, deletePost as deletePostApi, createPost } from '../../actions/posts';

interface Post {
    _id: string;
    title: string;
    content: string;
    author: string;
}

interface PostsState {
    posts: Post[];
    currentPost: Post | null;
    loading: boolean;
    error: string | null;
}

const initialState: PostsState = {
    posts: [],
    currentPost: null,
    loading: false,
    error: null,
};

export const fetchPosts = createAsyncThunk('posts/fetchPosts', async () => {
    const response = await getPosts();
    return response;
});

export const fetchPostById = createAsyncThunk('posts/fetchPostById', async (postId: string) => {
    const response = await getPostById(postId);
    return response;
});

export const deletePostById = createAsyncThunk('posts/deletePostById', async (postId: string) => {
    await deletePostApi(postId);
    return postId;
});

export const createNewPost = createAsyncThunk('posts/createNewPost', async ({ state, formData }: { state: any, formData: FormData }) => {
    const response = await createPost(state, formData);
    return response;
});

// Create the slice
const postsSlice = createSlice({
    name: 'posts',
    initialState,
    reducers: {
        setPosts: (state, action: PayloadAction<Post[]>) => {
            state.posts = action.payload;
        },
        addPost: (state, action: PayloadAction<Post>) => {
            state.posts.push(action.payload);
        },
        updatePost: (state, action: PayloadAction<Post>) => {
            const index = state.posts.findIndex(post => post._id === action.payload._id);
            if (index !== -1) {
                state.posts[index] = action.payload;
            }
        },
        deletePost: (state, action: PayloadAction<string>) => {
            state.posts = state.posts.filter(post => post._id !== action.payload);
        },
        setCurrentPost: (state, action: PayloadAction<Post | null>) => {
            state.currentPost = action.payload;
        },
        setCurrentPostById: (state, action: PayloadAction<string>) => {
            const post = state.posts.find(post => post._id === action.payload);
            if (post) {
                state.currentPost = post;
            } else {
                state.currentPost = null;
            }
        },
    },
    extraReducers: (builder) => {
        builder
            // Fetch posts
            .addCase(fetchPosts.pending, (state) => {
                state.loading = true;
            })
            .addCase(fetchPosts.fulfilled, (state, action) => {
                state.loading = false;
                state.posts = action.payload;
            })
            .addCase(fetchPosts.rejected, (state, action) => {
                state.loading = false;
                state.error = action.error.message || 'Failed to load posts';
            })

            // Fetch post by ID
            .addCase(fetchPostById.pending, (state) => {
                state.loading = true;
            })
            .addCase(fetchPostById.fulfilled, (state, action) => {
                state.loading = false;
                state.currentPost = action.payload;
            })
            .addCase(fetchPostById.rejected, (state, action) => {
                state.loading = false;
                state.error = action.error.message || 'Failed to load post';
            })

            // Delete post
            .addCase(deletePostById.pending, (state) => {
                state.loading = true;
            })
            .addCase(deletePostById.fulfilled, (state, action) => {
                state.loading = false;
                state.posts = state.posts.filter(post => post._id !== action.payload);
            })
            .addCase(deletePostById.rejected, (state, action) => {
                state.loading = false;
                state.error = action.error.message || 'Failed to delete post';
            })

            // Create post
            .addCase(createNewPost.pending, (state) => {
                state.loading = true;
            })
            .addCase(createNewPost.fulfilled, (state, action) => {
                state.loading = false;
                state.posts.push(action.payload);
            })
            .addCase(createNewPost.rejected, (state, action) => {
                state.loading = false;
                state.error = action.error.message || 'Failed to create post';
            });
    },
});

export const { setPosts, addPost, updatePost, deletePost, setCurrentPost, setCurrentPostById } = postsSlice.actions;
export default postsSlice.reducer;
```

## src/lib/redux/store.ts
```ts
import { configureStore } from '@reduxjs/toolkit';
import postsReducer from './postsSlice';
import { TypedUseSelectorHook, useDispatch, useSelector } from 'react-redux';

export const store = configureStore({
    reducer: {
        posts: postsReducer,
    },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;

export const useAppDispatch = () => useDispatch<AppDispatch>();
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector;
```

## src/components/Providers.tsx
```tsx
"use client";

import { Provider } from "react-redux";
import { SessionProvider } from "next-auth/react";
import { store } from "@/lib/redux/store";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <SessionProvider>
      <Provider store={store}>{children}</Provider>
    </SessionProvider>
  );
}
```

## src/app/layout.tsx
```tsx
import NavBar from "@/components/NavBar";
import "./globals.css";
import { Providers } from '@/components/Providers';
import { Toaster } from "react-hot-toast";

export default function RootLayout({ children }: {
  children: React.ReactNode
}) {
  return (
    <html>
      <body>
        <Providers>
          <NavBar />
          {children}
        </Providers>
        <Toaster position="top-right" />
      </body>
    </html>
  );
}
```
# src/app/api/auth/register/route.ts
```ts
import connectDB from '@/lib/db';
import User from '@/models/User';
import { SignupFormSchema } from '@/lib/definitions';
import { NextResponse } from 'next/server';
import { Password } from '@/lib/password';
import { ZodError } from 'zod';

export async function POST(req: Request) {
    try {
        await connectDB();
        const body = await req.json();

        const validatedData = SignupFormSchema.parse(body);

        const existingUser = await User.findOne({
            $or: [
                { email: validatedData.email },
                { username: validatedData.username }
            ]
        });

        if (existingUser) throw new Error("User with given email or user name already exists")

        // create a new user instance
        const newUser = new User({
            username: validatedData.username,
            email: validatedData.email,
            password: await Password.hash(validatedData.password)
        });

        // save the user into your database
        await newUser.save()

        return NextResponse.json(newUser, { status: 201 });

    } catch (error: any) {
        if (error instanceof ZodError) {
            return NextResponse.json(error.flatten().fieldErrors, { status: 422 });
        }
        console.log(error.message);

        return NextResponse.json(error.message, { status: 422 });
    }
}
```

## .env
```bash
MONGODB_URI='mongodb://localhost:27017/blog-db'
NEXTAUTH_SECRET='any secrete of your choice'
API_BASE_URL="http://localhost:3000/api"
```