<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Post;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class PostController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(): JsonResponse
    {
        $posts = Post::with('user')->get();
        return response()->json($posts);
    }

    /**
     * Store a newly created resource in storage.
     * Only users with 'admin' role can create posts
     */
    public function store(Request $request): JsonResponse
    {
        $request->validate([
            'title' => 'required|string|max:255',
            'content' => 'required',
        ]);

        $post = Post::create([
            'user_id' => Auth::id(),
            'title' => $request->title,
            'content' => $request->content,
        ]);

        return response()->json($post, 201);
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id): JsonResponse
    {
        $post = Post::with('user')->findOrFail($id);
        return response()->json($post);
    }

    /**
     * Update the specified resource in storage.
     * Only users with 'admin' role can update posts
     */
    public function update(Request $request, string $id): JsonResponse
    {
        $request->validate([
            'title' => 'sometimes|string|max:255',
            'content' => 'sometimes',
        ]);

        $post = Post::findOrFail($id);
        $post->update($request->only(['title', 'content']));

        return response()->json($post);
    }

    /**
     * Remove the specified resource from storage.
     * Only users with 'admin' role can delete posts
     */
    public function destroy(string $id): JsonResponse
    {
        $post = Post::findOrFail($id);
        $post->delete();

        return response()->json(['message' => 'Post deleted successfully']);
    }
}
