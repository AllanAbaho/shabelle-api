<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class JobApplication extends Model
{
    use HasFactory;

    /**
     * Get the owner of application.
     */
    public function user()
    {
        return $this->belongsTo(User::class,'created_by');
    }

    /**
     * Get the owner of application.
     */
    public function job()
    {
        return $this->belongsTo(Job::class,'job_id');
    }
}
