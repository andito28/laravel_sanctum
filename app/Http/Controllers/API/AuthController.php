<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Validator;
use Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\DB;

class AuthController extends Controller
{

    public function register(Request $request){
        
        $rules = [
            'name' => 'required',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|min:8'
        ];

        $validator = Validator::make($request->all(),$rules);

        if($validator->fails()){
            return response()->json($validator->errors(),401);
        }


       $save = DB::transaction(function() use($request){

                $user = new User;
                $user->name = $request->name;
                $user->email = $request->email;
                $user->password = Hash::make($request->password);
                $user->save();

                $token = $user->createToken('auth_token')->plainTextToken;

                $response = [
                    'message ' => 'Success Register User',
                    'data' => $user,
                    'access_token' => $token,
                    'token_type' => 'Bearer'
                ];

                return response()->json($response,200);
            });

        return $save;
    }

    public function login(Request $request){

        $sigIn = DB::transaction(function() use($request){

            if(!Auth::attempt($request->only('email','password'))){
                return response()->json(['message' => 'Unaothorized'],401);
            }

            $user = User::where('email',$request->email)->firstOrFail();

            $token = $user->createToken('auth_token')->plainTextToken;

            return response()->json([
                'message' => 'Login Succesfully',
                'data' => $user,
                'acces_token' => $token,
                'token_type' => 'Bearer'
            ]);
        });

        return $sigIn;

    }

    public function logout()
    {
        auth()->user()->tokens()->delete();

        return [
            'message' => 'You have successfully logged out and the token was successfully deleted'
        ];
    }
    
}
