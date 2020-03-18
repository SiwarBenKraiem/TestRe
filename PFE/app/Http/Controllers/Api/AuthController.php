<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;


class AuthController extends Controller
{
    public function login(Request $request)
    {
       $login= $request->validate([
            'email'=>'email|required',
             'password' =>'required|string'
            ]);
       if (!auth()->attempt($login)){
           return response(['message'=>'Invalid login credentials']);
       }
       $accessToken = auth()->user()->createToken('AuthToken')->accessToken;
       return response(['user' =>auth()->user() ,'access_token' => $accessToken]);
    }

    public function Register(Request $request)
    {
        $validate= $request->validate([
            'name'=>'required|max:55',
            'email'=>'email|required',
            'password' =>'required|confirmed'
        ]);
        $validate['password'] = bcrypt($request-> password);

        $user = User::create($validate);
        $accessToken = $user->createToken('AuthToken')->accessToken;
        return response(['user' => $user ,'access_token' => $accessToken]);

    }
}
