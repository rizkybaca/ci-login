<?php 

function is_logged_in()
{
	$ci=get_instance();
	if (!$ci->session->userdata('email')) {
		redirect('auth');
	} else {
		$role_id=$ci->session->userdata('role_id');
		$menu=$ci->uri->segment(1);

		$q_menu=$ci->db->get_where('user_menu', ['menu'=>$menu])->row_array();
		$menu_id=$q_menu['id'];

		$q_user_access=$ci->db->get_where('user_access_menu', [
			'role_id'=> $role_id,
			'menu_id'=>$menu_id
		]);

		if ($q_user_access->num_rows()<1) {
			redirect('auth/blocked');
		}
	}
}