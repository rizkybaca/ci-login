<!-- Sidebar -->
        <ul class="navbar-nav bg-gradient-primary sidebar sidebar-dark accordion" id="accordionSidebar">

            <!-- Sidebar - Brand -->
            <a class="sidebar-brand d-flex align-items-center justify-content-center" href="index.html">
                <div class="sidebar-brand-icon rotate-n-15">
                    <i class="fas fa-laugh-wink"></i>
                </div>
                <div class="sidebar-brand-text mx-3">CI | App</div>
            </a>

            <!-- Divider -->
            <hr class="sidebar-divider">

            <!-- get menu -->
            <?php 
              $role_id=$this->session->userdata('role_id');
              $q_menu="SELECT `user_menu`.`id`, `menu`
                        FROM `user_menu` JOIN `user_access_menu` 
                        ON `user_menu`.`id` = `user_access_menu`.`menu_id`
                        WHERE `user_access_menu`.`role_id` = $role_id
                        ORDER BY `user_access_menu`.`menu_id` ASC
                      ";
              $menu=$this->db->query($q_menu)->result_array();
            ?>

            <!-- loop menu -->
            <?php foreach ($menu as $m) : ?>

              <!-- Heading -->
              <div class="sidebar-heading">
                <?= $m['menu']; ?>
              </div>

              <!-- get sub-menu -->
              <?php 
                $menu_id=$m['id'];
                $q_sub="SELECT * FROM `user_sub_menu` WHERE `menu_id` = $menu_id AND `is_active` = 1";
                $sub=$this->db->query($q_sub)->result_array();
              ?>

              <?php foreach ($sub as $s) : ?>

                <!-- Nav Item - Dashboard -->
                <?php if ($title==$s['title']) : ?>
                  <li class="nav-item active">
                <?php else : ?>
                  <li class="nav-item">
                <?php endif; ?>
                  <a class="nav-link" href="<?= base_url($s['url']);  ?>">
                    <i class="<?= $s['icon']; ?>"></i>
                    <span><?= $s['title']; ?></span></a>
                </li>

              <?php endforeach; ?>

              <!-- Divider -->
              <hr class="sidebar-divider">

            <?php endforeach; ?>

            <!-- Nav Item - Logout -->
            <li class="nav-item">
                <a class="nav-link" href="<?= base_url('auth/logout'); ?>" data-toggle="modal" data-target="#logoutModal">
                    <i class="fas fa-sign-out-alt fa-fw"></i>
                    <span>Logout</span></a>
            </li>

            <!-- Divider -->
            <hr class="sidebar-divider d-none d-md-block">

            <!-- Sidebar Toggler (Sidebar) -->
            <div class="text-center d-none d-md-inline">
                <button class="rounded-circle border-0" id="sidebarToggle"></button>
            </div>

        </ul>
        <!-- End of Sidebar