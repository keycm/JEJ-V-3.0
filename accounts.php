<?php
// accounts.php
include 'config.php';

// Security Check: Only Admin
if(!isset($_SESSION['user_id']) || !in_array($_SESSION['role'], ['SUPER ADMIN', 'ADMIN', 'MANAGER'])){
    header("Location: login.php");
    exit();
}

$msg = "";
$msg_type = "";

// --- ACTIONS ---

// 0. Create Account
if(isset($_POST['action']) && $_POST['action'] == 'create_account'){
    $fullname = $conn->real_escape_string($_POST['fullname']);
    $email = $conn->real_escape_string($_POST['email']);
    $phone = $conn->real_escape_string($_POST['phone']);
    $password = md5($_POST['password']);
    $role = $conn->real_escape_string($_POST['role']);

    $check = $conn->query("SELECT * FROM users WHERE email='$email'");
    if($check->num_rows > 0){
        $msg = "Email is already registered.";
        $msg_type = "error";
    } else {
        $stmt = $conn->prepare("INSERT INTO users (fullname, phone, email, password, role) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssss", $fullname, $phone, $email, $password, $role);
        if($stmt->execute()){
            $new_id = $conn->insert_id;
            // AUDIT LOG: Account Creation
            logActivity($conn, $_SESSION['user_id'], "Created User Account", "Created $role account for $fullname ($email). ID: $new_id");
            
            $msg = "New account created successfully.";
            $msg_type = "success";
        } else {
            $msg = "Failed to create account.";
            $msg_type = "error";
        }
    }
}

// 1. Delete User & Archive
if(isset($_POST['action']) && $_POST['action'] == 'delete'){
    $id = $_POST['user_id'];
    if($id != $_SESSION['user_id']){
        
        // 1. Fetch info before deleting
        $u_info = $conn->query("SELECT * FROM users WHERE id='$id'")->fetch_assoc();
        if($u_info){
            $target_email = $u_info['email'];
            $target_role = $u_info['role'];
            
            // Remove the password hash before archiving for security
            unset($u_info['password']); 
            
            // 2. Archive to Delete History
            logDeletion($conn, 'User Accounts', $id, $u_info, $_SESSION['user_id']);
            
            // 3. AUDIT LOG
            logActivity($conn, $_SESSION['user_id'], "Deleted User Account", "Deleted $target_role account ($target_email). ID: $id");
        }

        // 4. Actually Delete
        $conn->query("DELETE FROM users WHERE id='$id'");
        
        $msg = "User account deleted successfully. Data moved to Archive.";
        $msg_type = "success";
    } else {
        $msg = "You cannot delete your own account.";
        $msg_type = "error";
    }
}

// 2. Change Role
if(isset($_POST['action']) && $_POST['action'] == 'change_role'){
    $id = $_POST['user_id'];
    $new_role = $_POST['new_role'];
    
    if($id != $_SESSION['user_id']){
        // Get old role for the log
        $old_role = $conn->query("SELECT role, email FROM users WHERE id='$id'")->fetch_assoc();
        
        $stmt = $conn->prepare("UPDATE users SET role=? WHERE id=?");
        $stmt->bind_param("si", $new_role, $id);
        $stmt->execute();
        
        // AUDIT LOG: Role Change
        logActivity($conn, $_SESSION['user_id'], "Changed User Role", "Updated role for {$old_role['email']} from {$old_role['role']} to $new_role. ID: $id");

        $msg = "User role updated to $new_role.";
        $msg_type = "success";
    } else {
        $msg = "You cannot change your own role.";
        $msg_type = "error";
    }
}

// Fetch Users
$users = $conn->query("SELECT * FROM users ORDER BY created_at DESC");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Management | JEJ Admin</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">

    <style>
        :root {
            /* NATURE GREEN THEME */
            --primary: #2e7d32; 
            --primary-light: #e8f5e9; 
            --dark: #1b5e20; 
            --gray-light: #f1f8e9; 
            --gray-border: #c8e6c9; 
            --text-muted: #607d8b; 
            
            --shadow-sm: 0 1px 2px 0 rgba(46, 125, 50, 0.08);
            --shadow-md: 0 4px 6px -1px rgba(46, 125, 50, 0.1), 0 2px 4px -1px rgba(46, 125, 50, 0.06);
            --shadow-lg: 0 10px 15px -3px rgba(46, 125, 50, 0.15), 0 4px 6px -2px rgba(46, 125, 50, 0.05);
        }

        body { background-color: #fafcf9; display: flex; min-height: 100vh; overflow-x: hidden; font-family: 'Inter', sans-serif; color: #37474f; margin: 0; }

        /* Sidebar Styling */
        .sidebar { width: 260px; background: #ffffff; border-right: 1px solid var(--gray-border); display: flex; flex-direction: column; position: fixed; height: 100vh; z-index: 100; box-shadow: var(--shadow-sm); }
        .brand-box { padding: 25px; border-bottom: 1px solid var(--gray-border); display: flex; align-items: center; gap: 12px; }
        .sidebar-menu { padding: 20px 15px; flex: 1; overflow-y: auto; }
        .menu-link { display: flex; align-items: center; gap: 12px; padding: 12px 18px; color: #455a64; text-decoration: none; font-weight: 500; font-size: 14px; border-radius: 10px; margin-bottom: 6px; transition: all 0.2s ease; }
        .menu-link:hover { background: var(--gray-light); color: var(--primary); }
        .menu-link.active { background: var(--primary-light); color: var(--primary); font-weight: 600; border-left: 4px solid var(--primary); }
        .menu-link i { width: 20px; text-align: center; font-size: 16px; opacity: 0.8; }
        
        /* Main Panel & Header */
        .main-panel { margin-left: 260px; flex: 1; padding: 0; width: calc(100% - 260px); display: flex; flex-direction: column; }
        
        .top-header { display: flex; justify-content: space-between; align-items: center; background: #ffffff; padding: 20px 40px; border-bottom: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); z-index: 50; }
        .header-title h1 { font-size: 22px; font-weight: 800; color: var(--dark); margin: 0 0 4px 0; letter-spacing: -0.5px;}
        .header-title p { color: var(--text-muted); font-size: 13px; margin: 0; }

        /* Profile Dropdown */
        .profile-dropdown { position: relative; cursor: pointer; }
        .profile-trigger { display: flex; align-items: center; gap: 12px; padding: 6px 12px; border-radius: 10px; transition: background 0.2s; border: 1px solid transparent; }
        .profile-trigger:hover { background: var(--gray-light); border-color: var(--gray-border); }
        .profile-avatar { width: 40px; height: 40px; background: var(--primary); color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 16px; box-shadow: 0 2px 4px rgba(46, 125, 50, 0.2);}
        .profile-info strong { display: block; font-size: 13px; color: var(--dark); line-height: 1.2; }
        .profile-info small { font-size: 11px; color: var(--text-muted); font-weight: 500; }
        
        .dropdown-menu { display: none; position: absolute; right: 0; top: 110%; background: white; border-radius: 12px; box-shadow: var(--shadow-lg); border: 1px solid var(--gray-border); min-width: 200px; z-index: 1000; overflow: hidden; transform-origin: top right; animation: dropAnim 0.2s ease-out forwards; }
        @keyframes dropAnim { 0% { opacity: 0; transform: scale(0.95) translateY(-10px); } 100% { opacity: 1; transform: scale(1) translateY(0); } }
        .profile-dropdown:hover .dropdown-menu { display: block; }
        .dropdown-header { padding: 15px; border-bottom: 1px solid var(--gray-border); background: var(--gray-light); }
        .dropdown-item { padding: 12px 16px; display: flex; align-items: center; gap: 12px; color: #455a64; text-decoration: none; font-size: 13px; font-weight: 500; transition: background 0.2s; border-left: 3px solid transparent;}
        .dropdown-item:hover { background: var(--primary-light); color: var(--primary); border-left-color: var(--primary); }
        .dropdown-item.text-danger { color: #d84315; }
        .dropdown-item.text-danger:hover { background: #fbe9e7; color: #bf360c; border-left-color: #d84315; }

        .content-area { padding: 35px 40px; flex: 1; }

        /* Alerts & Banners */
        .alert-banner { padding: 16px 20px; border-radius: 10px; margin-bottom: 25px; font-weight: 500; font-size: 14px; box-shadow: var(--shadow-sm); display: flex; align-items: center; gap: 12px;}
        .alert-success { background: #e8f5e9; color: #2e7d32; border: 1px solid #c8e6c9; }
        .alert-error { background: #ffebee; color: #c62828; border: 1px solid #ffcdd2; }

        /* Create Account Form Card */
        .form-card { background: white; padding: 25px; border-radius: 16px; border: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); margin-bottom: 30px; }
        .form-card h3 { margin: 0 0 20px 0; font-size: 16px; font-weight: 800; color: #1e293b; border-bottom: 1px solid var(--gray-border); padding-bottom: 15px; display: flex; align-items: center;}
        
        .form-control { width: 100%; padding: 10px 14px; border: 1px solid #cbd5e1; border-radius: 8px; font-family: inherit; font-size: 13px; outline: none; transition: 0.2s; box-sizing: border-box;}
        .form-control:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(46, 125, 50, 0.15); }
        
        /* Table Styling */
        .table-container { background: white; border-radius: 16px; border: 1px solid var(--gray-border); box-shadow: var(--shadow-sm); overflow: hidden; margin-bottom: 30px; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 16px 24px; font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; background: var(--gray-light); border-bottom: 1px solid var(--gray-border); letter-spacing: 0.5px;}
        td { padding: 16px 24px; border-bottom: 1px solid var(--gray-border); color: #37474f; font-size: 14px; vertical-align: middle; }
        tr:hover td { background: #fdfdfd; }
        tr:last-child td { border-bottom: none; }

        /* Badges */
        .role-badge { padding: 5px 10px; border-radius: 6px; font-size: 10px; font-weight: 800; text-transform: uppercase; display: inline-block; border: 1px solid transparent;}
        .role-SUPER-ADMIN, .role-ADMIN { background: #ede9fe; color: #7c3aed; border-color: #ddd6fe; } /* Violet */
        .role-MANAGER { background: #dbeafe; color: #2563eb; border-color: #bfdbfe; } /* Blue */
        .role-AGENT { background: #d1fae5; color: #059669; border-color: #a7f3d0; } /* Emerald */
        .role-BUYER { background: #f1f5f9; color: #475569; border-color: #e2e8f0; } /* Slate */

        /* Buttons */
        .btn-action { background: var(--primary); color: white; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 600; font-size: 13px; cursor: pointer; transition: 0.2s; display: inline-flex; align-items: center; gap: 6px; box-shadow: var(--shadow-sm);}
        .btn-action:hover { background: var(--dark); transform: translateY(-1px); }

        .btn-mini { border: none; padding: 7px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 700; color: white; transition: 0.2s; display: inline-flex; align-items: center; justify-content: center;}
        .btn-del { background: #ef4444; } .btn-del:hover { background: #dc2626; transform: translateY(-1px); } /* Red */
        .btn-promote { background: #10b981; } .btn-promote:hover { background: #059669; transform: translateY(-1px); } /* Emerald */
        
        .role-select { padding: 7px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 11px; font-weight: 700; color: #475569; outline:none; transition: 0.2s; font-family: inherit;}
        .role-select:focus { border-color: var(--primary); }
    </style>
</head>
<body>

    <div class="sidebar">
        <div class="brand-box">
            <img src="assets/logo.png" style="height: 38px; width: auto; border-radius: 8px;">
            <div style="line-height: 1.1;">
                <span style="font-size: 16px; font-weight: 800; color: var(--primary); display: block;">JEJ Surveying</span>
                <span style="font-size: 11px; color: var(--text-muted); font-weight: 500;">Management Portal</span>
            </div>
        </div>
        
        <div class="sidebar-menu">
            <small style="padding: 0 15px; color: #90a4ae; font-weight: 700; font-size: 11px; display: block; margin-bottom: 12px; letter-spacing: 0.5px;">MAIN MENU</small>
            <a href="admin.php?view=dashboard" class="menu-link"><i class="fa-solid fa-chart-pie"></i> Dashboard</a>
            <a href="reservation.php" class="menu-link"><i class="fa-solid fa-file-signature"></i> Reservations</a>
            <a href="master_list.php" class="menu-link"><i class="fa-solid fa-map-location-dot"></i> Master List / Map</a>
            <a href="admin.php?view=inventory" class="menu-link"><i class="fa-solid fa-plus-circle"></i> Add Property</a>
            <a href="financial.php" class="menu-link"><i class="fa-solid fa-coins"></i> Financials</a>
            <a href="transaction_history.php" class="menu-link" style="padding-left: 35px; font-size: 13px;"><i class="fa-solid fa-list-ul" style="font-size: 12px;"></i> Ledger List</a>
            <a href="payment_tracking.php" class="menu-link"><i class="fa-solid fa-file-invoice-dollar"></i> Payment Tracking</a>
            
            <small style="padding: 0 15px; color: #90a4ae; font-weight: 700; font-size: 11px; display: block; margin-top: 25px; margin-bottom: 12px; letter-spacing: 0.5px;">MANAGEMENT</small>
            <a href="accounts.php" class="menu-link active"><i class="fa-solid fa-users-gear"></i> Accounts</a>
            <a href="delete_history.php" class="menu-link"><i class="fa-solid fa-trash-can"></i> Delete History</a>
            
            <small style="padding: 0 15px; color: #90a4ae; font-weight: 700; font-size: 11px; display: block; margin-top: 25px; margin-bottom: 12px; letter-spacing: 0.5px;">SYSTEM</small>
            <a href="index.php" class="menu-link" target="_blank"><i class="fa-solid fa-globe"></i> View Website</a>
        </div>
    </div>

    <div class="main-panel">
        
        <div class="top-header">
            <div class="header-title">
                <h1>Account Management</h1>
                <p>Manage registered users, administrators, and system access levels.</p>
            </div>
            
            <div class="profile-dropdown">
                <div class="profile-trigger">
                    <div class="profile-avatar">A</div>
                    <div class="profile-info">
                        <strong>Administrator</strong>
                        <small>System Admin <i class="fa-solid fa-chevron-down" style="font-size: 9px; margin-left: 3px;"></i></small>
                    </div>
                </div>
                
                <div class="dropdown-menu">
                    <div class="dropdown-header">
                        <strong style="display: block; font-size: 13px; color: var(--dark);">JEJ Admin System</strong>
                        <span style="font-size: 11px; color: var(--text-muted);">Logged in successfully</span>
                    </div>
                    <a href="audit_logs.php" class="dropdown-item"><i class="fa-solid fa-clock-rotate-left" style="width:16px;"></i> System Audit Logs</a>
                    <a href="settings.php" class="dropdown-item"><i class="fa-solid fa-gear" style="width:16px;"></i> Account Settings</a>
                    <div style="height: 1px; background: var(--gray-border); margin: 5px 0;"></div>
                    <a href="logout.php" class="dropdown-item text-danger"><i class="fa-solid fa-arrow-right-from-bracket" style="width:16px;"></i> Secure Logout</a>
                </div>
            </div>
        </div>

        <div class="content-area">

            <?php if($msg): ?>
                <div class="alert-banner <?= $msg_type=='success' ? 'alert-success' : 'alert-error' ?>">
                    <i class="fa-solid <?= $msg_type=='success'?'fa-check-circle':'fa-circle-exclamation' ?>"></i>
                    <?= $msg ?>
                </div>
            <?php endif; ?>

            <div class="form-card">
                <h3><i class="fa-solid fa-user-plus" style="color: var(--primary); margin-right: 8px;"></i> Create New Account</h3>
                <form method="POST" style="display: flex; gap: 15px; flex-wrap: wrap; align-items: flex-end;">
                    <input type="hidden" name="action" value="create_account">
                    
                    <div style="flex: 1; min-width: 180px;">
                        <label style="display:block; font-size:12px; font-weight:700; color:#475569; margin-bottom:6px;">Full Name</label>
                        <input type="text" name="fullname" class="form-control" required placeholder="John Doe">
                    </div>
                    
                    <div style="flex: 1; min-width: 180px;">
                        <label style="display:block; font-size:12px; font-weight:700; color:#475569; margin-bottom:6px;">Email Address</label>
                        <input type="email" name="email" class="form-control" required placeholder="john@example.com">
                    </div>
                    
                    <div style="flex: 1; min-width: 140px;">
                        <label style="display:block; font-size:12px; font-weight:700; color:#475569; margin-bottom:6px;">Phone Number</label>
                        <input type="text" name="phone" class="form-control" placeholder="0912 345 6789">
                    </div>

                    <div style="flex: 1; min-width: 140px;">
                        <label style="display:block; font-size:12px; font-weight:700; color:#475569; margin-bottom:6px;">Password</label>
                        <input type="password" name="password" class="form-control" required placeholder="••••••••">
                    </div>
                    
                    <div style="flex: 1; min-width: 140px;">
                        <label style="display:block; font-size:12px; font-weight:700; color:#475569; margin-bottom:6px;">System Role</label>
                        <select name="role" class="form-control" required>
                            <option value="BUYER">BUYER</option>
                            <option value="AGENT">AGENT</option>
                            <option value="MANAGER">MANAGER</option>
                            <option value="ADMIN">ADMIN</option>
                            <option value="SUPER ADMIN">SUPER ADMIN</option>
                        </select>
                    </div>
                    
                    <div>
                        <button type="submit" class="btn-action"><i class="fa-solid fa-plus"></i> Create Account</button>
                    </div>
                </form>
            </div>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 15%;">Account ID</th>
                            <th style="width: 35%;">User Details</th>
                            <th style="width: 20%;">Current Role</th>
                            <th style="width: 30%;">Management Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while($row = $users->fetch_assoc()): ?>
                        <tr>
                            <td style="font-weight: 700; color: #64748b;">#<?= $row['id'] ?></td>
                            <td>
                                <strong style="color: #1e293b; font-size: 14px; display:block; margin-bottom: 2px;"><?= htmlspecialchars($row['fullname']) ?></strong>
                                <span style="color: #64748b; font-size: 12px;"><i class="fa-regular fa-envelope" style="font-size:10px;"></i> <?= htmlspecialchars($row['email']) ?></span>
                            </td>
                            <td>
                                <span class="role-badge role-<?= str_replace(' ', '-', $row['role'] ?: 'BUYER') ?>">
                                    <?= $row['role'] ?: 'BUYER' ?>
                                </span>
                            </td>
                            <td>
                                <?php if($row['id'] != $_SESSION['user_id']): ?>
                                    <div style="display: flex; gap: 8px; align-items: center;">
                                        <form method="POST" style="display: flex; gap: 8px; align-items: center; margin: 0;">
                                            <input type="hidden" name="action" value="change_role">
                                            <input type="hidden" name="user_id" value="<?= $row['id'] ?>">
                                            <select name="new_role" class="role-select">
                                                <option value="BUYER" <?= $row['role'] == 'BUYER' ? 'selected' : '' ?>>BUYER</option>
                                                <option value="AGENT" <?= $row['role'] == 'AGENT' ? 'selected' : '' ?>>AGENT</option>
                                                <option value="MANAGER" <?= $row['role'] == 'MANAGER' ? 'selected' : '' ?>>MANAGER</option>
                                                <option value="ADMIN" <?= $row['role'] == 'ADMIN' ? 'selected' : '' ?>>ADMIN</option>
                                                <option value="SUPER ADMIN" <?= $row['role'] == 'SUPER ADMIN' ? 'selected' : '' ?>>SUPER ADMIN</option>
                                            </select>
                                            <button class="btn-mini btn-promote" title="Update Role"><i class="fa-solid fa-check"></i></button>
                                        </form>

                                        <form method="POST" style="display:inline; margin: 0;" onsubmit="return confirm('Are you sure you want to archive and delete this user?');">
                                            <input type="hidden" name="action" value="delete">
                                            <input type="hidden" name="user_id" value="<?= $row['id'] ?>">
                                            <button class="btn-mini btn-del" title="Delete User"><i class="fa-solid fa-trash"></i></button>
                                        </form>
                                    </div>
                                <?php else: ?>
                                    <span style="font-size: 12px; color: #94a3b8; font-style: italic; font-weight:600;"><i class="fa-solid fa-lock" style="font-size:10px; margin-right: 3px;"></i> Current User (You)</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

</body>
</html>