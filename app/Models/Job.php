<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Job extends Model
{
    use HasFactory;

    /**
     * Get the comments for the blog post.
     */
    public function applications()
    {
        return $this->hasMany(JobApplication::class);
    }
}
