<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Exceptions\JWTException;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth as FacadesJWTAuth;

class ApiController extends Controller
{

    public function register(Request $request)
    {
        // Validate data
        $validator = Validator::make($request->all(), [
            'name' => 'required|string',
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:6|max:50'
        ]);

        if ($validator->fails()) {
            // Send detailed error response for validation failure
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Create a new user
        $user = User::create([
            'name' => $request->input('name'),
            'email' => $request->input('email'),
            'password' => Hash::make($request->input('password'))
        ]);

        if (!$user) {
            // Handle failure to create user
            return response()->json([
                'success' => false,
                'message' => 'Failed to create user'
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Return success response with created user data
        return response()->json([
            'success' => true,
            'message' => 'User created successfully',
            'data' => $user
        ], Response::HTTP_CREATED);
    }


    public function authenticate(Request $request)
    {
        $credentials = $request->only('email', 'password');

        // Validate the credentials
        $validator = Validator::make($credentials, [
            'email' => 'required|email',
            'password' => 'required|string|min:6|max:50'
        ]);

        // Send a detailed error response if the request is invalid
        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        try {
            // Attempt to generate JWT token
            $jwtAuth = FacadesJWTAuth::attempt($credentials);

            if (!$jwtAuth) {
                // Invalid credentials
                return response()->json([
                    'success' => false,
                    'message' => 'Login credentials are invalid.',
                ], Response::HTTP_BAD_REQUEST);
            }

            // Token created, return a success response with JWT token
            return response()->json([
                'success' => true,
                'token' => $jwtAuth,
            ], Response::HTTP_OK);
        } catch (JWTException $e) {
            // Could not create a token
            return response()->json([
                'success' => false,
                'message' => 'Could not create token.',
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function logout(Request $request)
    {
        $validator = Validator::make($request->only('token'), [
            'token' => 'required'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid token or missing token',
            ], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        try {
            FacadesJWTAuth::invalidate($request->token);

            return response()->json([
                'success' => true,
                'message' => 'User has been logged out'
            ]);
        } catch (JWTException $exception) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to log out user'
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function get_user(Request $request)
    {
        try {
            $user = auth()->user();
            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'User not found'
                ], Response::HTTP_NOT_FOUND);
            }

            return response()->json(['success' => true, 'user' => $user]);
        } catch (JWTException $exception) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to retrieve user'
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}