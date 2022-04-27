<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use App\Traits\ApiResponse;
use App\Http\Requests\LoginRequest;
use App\Http\Controllers\Controller;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use App\Http\Requests\RegisterRequest;
use Illuminate\Http\Exceptions\HttpResponseException;

class AuthController extends Controller
{
    //
    use ApiResponse;
    


    public function register(RegisterRequest $request){
        $validated = $request->validated();
        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
        ]);

        $token = $user->createToken('authToken')->plainTextToken;
        return $this -> apiSuccess([
            'token' => $token,
            'token_type' => 'Bearer',
            'user' => $user,
        ]);
    }

    public function login(LoginRequest $request){
        $validated = $request->validated();

        if(!auth()->attempt($validated)){
            return $this->apiError('Credentials not match', Response::HTTP_UNAUTHORIZED);
        }

        $user = User::where('email', $validated['email'])->first();
        $token = $user->createToken('authToken')->plainTextToken;

        return $this -> apiSuccess([
            'token' => $token,
            'token_type' => 'Bearer',
            'user' => $user,
        ]);
    }

    // public function logout() {
    //     try {
    //         auth()->user()->tokens()->delete();
    //         return $this -> apiSucces('Token revoked');

    //     } catch (\Throwable $e) {
    //             throw new HttpResponseException($this->apiError(
    //             null,
    //             Response::HTTP_INTERNAL_SERVER_ERROR,
    //         ));
    //     }
    // }
}
