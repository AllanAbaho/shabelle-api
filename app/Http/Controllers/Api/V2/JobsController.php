<?php

namespace App\Http\Controllers\Api\V2;

use Illuminate\Http\Request;
use App\Models\Job;
use App\Models\JobApplication;
use Illuminate\Support\Facades\Validator;

class JobsController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'sector' => 'required',
        ]);
        if ($validator->fails()) {
            return response()->json(["errors" => $validator->errors(),'status' => false]);
        }

        $jobs = Job::where('category',$request->sector)->with('applications.user')->get();
        return response(['status' => true, 'jobs' => $jobs]);
    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function postedJobs(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'created_by' => 'required',
        ]);
        if ($validator->fails()) {
            return response()->json(["errors" => $validator->errors(),'status' => false]);
        }

        $jobs = Job::where('created_by',$request->created_by)->with('applications.user')->get();
        return response(['status' => true, 'jobs' => $jobs]);
    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function appliedJobs(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'applicant_id' => 'required',
        ]);
        if ($validator->fails()) {
            return response()->json(["errors" => $validator->errors(),'status' => false]);
        }

        $applications = JobApplication::where('applicant_id',$request->applicant_id)->pluck('job_id')->toArray();
        $jobs = Job::whereIn('id',$applications)->with('applications.user')->get();
        return response(['status' => true, 'jobs' => $jobs]);
    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function getSingleJob($id)
    {
        $job = Job::where('id',$id)->with('applications')->first();
        return response(['status' => true, 'job' => $job]);
    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function changeJobStatus(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'job_id' => 'required',
            'status' => 'required',
        ]);
        if ($validator->fails()) {
            return response()->json(["errors" => $validator->errors(), 'status' => false]);
        }
        try {
            $job = Job::where('id',$request->job_id)->first();
            $job->status = $request->status;
            $job->save();
            return response(['status' => true, 'message' => 'Job status changed successfully']);
        } catch (\Exception $e) {
            return response(['status' => false, 'message' => 'Job status could not be changed','error'=>$e->getMessage()]);
        }
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'price' => 'required',
            'duration' => 'required',
            'location' => 'required',
            'type' => 'required',
            'description' => 'required',
            'category' => 'required',
            'deadline' => 'required',
            'status' => 'required',
            'created_by' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json(["errors" => $validator->errors(), 'status' => false]);
        }
        try {

            $job = new Job();
            $job->name = $request->name;
            $job->price = $request->price;
            $job->duration = $request->duration;
            $job->location = $request->location;
            $job->type = $request->type;
            $job->description = $request->description;
            $job->category = $request->category;
            $job->deadline = $request->deadline;
            $job->status = $request->status;
            $job->created_by = $request->created_by;
            $job->updated_by = $request->created_by;
            $job->save();
            return response(['status' => true, 'message' => 'Job posted successfully']);
        } catch (\Exception $e) {
            return response(['status' => false, 'message' => 'Job could not be posted']);
        }
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function edit($id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        //
    }
}
