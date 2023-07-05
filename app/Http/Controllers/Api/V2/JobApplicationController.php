<?php

namespace App\Http\Controllers\Api\V2;

use App\Models\JobApplication;
use App\Models\Job;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class JobApplicationController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        //
    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create()
    {
        //
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
            'job_id' => 'required',
            'applicant_id' => 'required',
            'status' => 'required',
            'portfolio' => 'required',
            'created_by' => 'required',
            'file' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json(["errors" => $validator->errors(), 'status' => false]);
        }

        $alreadyApplied = JobApplication::where('job_id',$request->job_id)->where('created_by',$request->applicant_id)->first();
        if($alreadyApplied){
            return response(['status' => false, 'message' => 'Sorry, You already applied for this job']);
        }
        try {
            $file = $request->file;
            $file = base64_decode($file);
            $dir = public_path('uploads/docs');
            $full_path = "$dir/$request->portfolio";
            file_put_contents($full_path, $file); // int or false
            $filePath = "uploads/docs/$request->portfolio";

            $jobApplication = new JobApplication();
            $jobApplication->job_id = $request->job_id;
            $jobApplication->applicant_id = $request->applicant_id;
            $jobApplication->status = $request->status;
            $jobApplication->portfolio = $filePath;
            $jobApplication->created_by = $request->created_by;
            $jobApplication->updated_by = $request->created_by;
            $jobApplication->save();
            return response(['status' => true, 'message' => 'Application submitted successfully']);
        } catch (\Exception $e) {
            return response(['status' => false, 'message' => 'Application could not be submitted','error'=>$e->getMessage()]);
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
    public function updateJobApplication(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'job_application_id' => 'required',
            'status' => 'required',
            'updated_by' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json(["errors" => $validator->errors(), 'status' => false]);
        }
        try {
            $jobApplication = JobApplication::where('id',$request->job_application_id)->first();
            $jobApplication->status = $request->status;
            $jobApplication->updated_by = $request->updated_by;
            $jobApplication->save();
            return response(['status' => true, 'message' => 'Application updated successfully']);
        } catch (\Exception $e) {
            return response(['status' => false, 'message' => 'Application could not be updated','error'=>$e->getMessage()]);
        }

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
