<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Auth extends CI_Controller
{

	public function __construct()
	{
		parent::__construct();
		$this->load->library('form_validation');
	}

	public function index()
	{

		if ($this->session->userdata('email')) {
			redirect('user');
		}

		$this->form_validation->set_rules('email', 'Email', 'required|trim|valid_email');
		$this->form_validation->set_rules('password', 'Password', 'required|trim');
		if ($this->form_validation->run()==FALSE) {
			$data['title']='CI | Login Page';
			$this->load->view('templates/auth_header', $data);
			$this->load->view('auth/login');
			$this->load->view('templates/auth_footer');
		} else {
			$this->_login();
		}
	}

	private function _login()
	{
		$email=$this->input->post('email');
		$password=$this->input->post('password');

		$user=$this->db->get_where('user', ['email'=>$email])->row_array();

		if ($user) {
			if ($user['is_active']==1) {
				if (password_verify($password, $user['password'])) {
					$data=[
						'email'=>$user['email'],
						'role_id'=>$user['role_id']
					];
					$this->session->set_userdata($data);
					if ($user['role_id']==1) {
						redirect('admin/index');
					} else {
						redirect('user/index');
					}
				} else {
					$this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">Wrong password.</div>');
					redirect('auth');
				}
			} else {
				$this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">This email has not been activated.</div>');
				redirect('auth');
			}
		} else {
			$this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">Email is not registered.</div>');
			redirect('auth');
		}

	}

	public function regist()
	{
		if ($this->session->userdata('email')) {
			redirect('user');
		}
		$this->form_validation->set_rules('name', 'Name', 'required|trim');
		$this->form_validation->set_rules('email', 'Email', 'required|trim|valid_email|is_unique[user.email]', [
			'is_unique' => 'Email has already registered!'
		]);
		$this->form_validation->set_rules('password1', 'Password', 'required|trim|min_length[4]|matches[password2]', [
			'matches' => 'Password dont match!',
			'min_length' => 'Password too short!'
		]);
		$this->form_validation->set_rules('password2', 'Password', 'required|trim|matches[password1]');


		if ($this->form_validation->run()==FALSE) {
			$data['title']='CI | Registration Page';
			$this->load->view('templates/auth_header', $data);
			$this->load->view('auth/regist');
			$this->load->view('templates/auth_footer');
		} else {
			$email=$this->input->post('email', true);
			$data=[
				'name'=>htmlspecialchars($this->input->post('name', true)),
				'email'=>htmlspecialchars($email),
				'password'=>htmlspecialchars(password_hash($this->input->post('password1', true), PASSWORD_DEFAULT)),
				'image'=>'default.jpg',
				'role_id'=>2,
				'is_active'=>0,
				'date_created'=>time()
			];

			$token=base64_encode(random_bytes(32)) ;
			$user_token=[
				'email'=>$email,
				'token'=>$token,
				'date_created'=>time()
			];

			$this->db->insert('user', $data);
			$this->db->insert('user_token', $user_token);

			$this->_sendEmail($token, 'verify');

			$this->session->set_flashdata('message', '<div class="alert alert-success" role="alert">Congratulation! Your account has been created. Please activate your account.</div>');
			redirect('auth');
		}
	}

	private function _sendEmail($token, $type)
	{
		$config=[
			'protocol'=>'smtp',
			'smtp_host'=>'ssl://smtp.googlemail.com',
			'smtp_user'=>'study.ci.21@gmail.com',
			'smtp_pass'=>'Drinking21',
			'smtp_port'=>465,
			'mailtype'=>'html',
			'charset'=>'utf-8',
			'newline'=>"\r\n"
		];
		$this->load->library('email', $config);
		$this->email->initialize($config);

		$this->email->from('study.ci.21@gmail.com', 'Study CI');
		$this->email->to($this->input->post('email', true));
		if ($type=='verify') {
			$this->email->subject('Account Verification');
			$this->email->message('Click this link to verify your CI APP account :<a href="'.base_url().'auth/verify?email='.$this->input->post('email').'&token='.urlencode($token). '">Activate</a>');
		}
		

		if ($this->email->send()) {
			return true;
		} else {
			echo $this->email->print_debugger();
			die;
		}
	}

	public function verify()
	{
		$email=$this->input->get('email');
		$token=$this->input->get('token');

		$q_user=$this->db->get_where('user', ['email'=>$email])->row_array();

		if ($q_user) {
			$q_token=$this->db->get_where('user_token', ['token'=>$token])->row_array();

			if ($q_token) {
				if (time()-$q_token['date_created']<(60*60*24)) {
					$this->db->set('is_active', 1);
					$this->db->where('email', $email);
					$this->db->update('user');

					$this->db->delete('user_token', ['email'=>$email]);
					$this->session->set_flashdata('message', '<div class="alert alert-success" role="alert">'.$email.' has been activated! Please login.</div>');
					redirect('auth');
				} else {
					$this->db->delete('user', ['email'=>$email]);
					$this->db->delete('user_token', ['email'=>$email]);
					$this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">Account activation failed! Token expired.</div>');
					redirect('auth');
				}
			} else {
				$this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">Account activation failed! Wrong token.</div>');
				redirect('auth');
			}
		} else {
			$this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">Account activation failed! Wrong email.</div>');
			redirect('auth');
		}

	}

	public function logout()
	{
		$this->session->unset_userdata('email');
		$this->session->unset_userdata('role_id');

		$this->session->set_flashdata('message', '<div class="alert alert-success" role="alert">You have been logged out</div>');
		redirect('auth');
	}

	public function blocked()
	{
		$data['title']='My Profile';
		$this->load->view('auth/blocked',$data);
		
	}

}
