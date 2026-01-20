<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Validation\Rules;
use Illuminate\View\View;

class RegisteredUserController extends Controller
{
    /**
     * Display the registration view.
     */
    public function create(): View
    {
        return view('auth.register');
    }

    /**
     * Handle an incoming registration request.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function store(Request $request): RedirectResponse
    {
        // Validate input with strong password rules
        $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'lowercase', 'email', 'max:255', 'unique:'.User::class],
            'password' => [
                'required',
                'confirmed',
                Rules\Password::min(8)   // Minimum 8 characters
                    ->letters()           // At least one letter
                    ->mixedCase()         // At least one uppercase & one lowercase
                    ->numbers()           // At least one number
                    ->symbols()           // At least one special character
            ],
        ]);

        // Create the user
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        // Trigger registered event
        event(new Registered($user));

        // Send a simple welcome email (no Blade needed)
        Mail::raw("Hello $user->name, Welcome to My App!", function ($message) use ($user) {
            $message->to($user->email)
                    ->subject("Welcome to My App");
        });

        // Login the user
        Auth::login($user);

        // Redirect to dashboard
        return redirect(route('dashboard', absolute: false));
    }
}
