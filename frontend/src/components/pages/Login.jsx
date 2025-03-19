import React, { useState } from 'react';
import {
    Box,
    Button,
    Checkbox,
    Container,
    FormControlLabel,
    Grid,
    TextField,
    Typography,
    Link,
    AppBar,
    Toolbar,
    Menu,
    MenuItem,
    IconButton,
    Switch,
    styled
} from '@mui/material';
import KeyboardArrowDownIcon from '@mui/icons-material/KeyboardArrowDown';

// Custom styled components to match the design in the image
const StyledAppBar = styled(AppBar)(({ theme }) => ({
    background: 'rgba(21, 21, 41, 0.7)',
    backdropFilter: 'blur(10px)',
    boxShadow: 'none',
    borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
}));

const StyledButton = styled(Button)(({ theme }) => ({
    backgroundColor: '#0d6efd',
    color: 'white',
    borderRadius: '8px',
    padding: '8px 16px',
    '&:hover': {
        backgroundColor: '#0b5ed7',
    },
}));

const SignInButton = styled(Button)(({ theme }) => ({
    backgroundColor: '#0d6efd',
    color: 'white',
    borderRadius: '8px',
    padding: '12px',
    width: '100%',
    fontSize: '1rem',
    marginTop: '20px',
    '&:hover': {
        backgroundColor: '#0b5ed7',
    },
}));

const StyledTextField = styled(TextField)(({ theme }) => ({
    '& .MuiOutlinedInput-root': {
        borderRadius: '8px',
        backgroundColor: 'rgba(255, 255, 255, 0.1)',
        '& fieldset': {
            borderColor: 'rgba(255, 255, 255, 0.2)',
        },
        '&:hover fieldset': {
            borderColor: 'rgba(255, 255, 255, 0.3)',
        },
        '&.Mui-focused fieldset': {
            borderColor: '#0d6efd',
        },
    },
    '& .MuiInputLabel-root': {
        color: 'rgba(255, 255, 255, 0.7)',
    },
    '& .MuiInputBase-input': {
        color: 'white',
    },
}));

const StyledFormControlLabel = styled(FormControlLabel)(({ theme }) => ({
    '& .MuiTypography-root': {
        color: 'white',
        fontSize: '0.875rem',
    },
}));

const BlueSwitch = styled(Switch)(({ theme }) => ({
    '& .MuiSwitch-switchBase.Mui-checked': {
        color: '#0d6efd',
        '&:hover': {
            backgroundColor: 'rgba(13, 110, 253, 0.08)',
        },
    },
    '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': {
        backgroundColor: '#0d6efd',
    },
}));

// Main component
const Login = () => {
    // State for dropdown menus
    const [pagesAnchorEl, setPagesAnchorEl] = useState(null);
    const [authAnchorEl, setAuthAnchorEl] = useState(null);
    const [appAnchorEl, setAppAnchorEl] = useState(null);
    const [ecommerceAnchorEl, setEcommerceAnchorEl] = useState(null);

    // Handle menu opening and closing
    const handleMenuOpen = (event, setAnchorEl) => {
        setAnchorEl(event.currentTarget);
    };

    const handleMenuClose = (setAnchorEl) => {
        setAnchorEl(null);
    };

    return (
        <Box
            sx={{
                minHeight: '100vh',
                display: 'flex',
                flexDirection: 'column',
                backgroundColor: '#131129',
                backgroundImage: 'linear-gradient(to right, #1a1942, #131129)',
            }}
        >
            {/* Navigation Bar */}
            <StyledAppBar position="static">
                <Toolbar>
                    <Typography variant="h6" sx={{ flexGrow: 0, color: 'white', fontWeight: 700, mr: 4 }}>
                        VISION UI PRO
                    </Typography>

                    {/* Navigation Menu Items */}
                    <Box sx={{ flexGrow: 1, display: 'flex' }}>
                        <Button
                            color="inherit"
                            endIcon={<KeyboardArrowDownIcon />}
                            onClick={(e) => handleMenuOpen(e, setPagesAnchorEl)}
                            sx={{ color: 'white' }}
                        >
                            Pages
                        </Button>
                        <Menu
                            anchorEl={pagesAnchorEl}
                            open={Boolean(pagesAnchorEl)}
                            onClose={() => handleMenuClose(setPagesAnchorEl)}
                        >
                            <MenuItem onClick={() => handleMenuClose(setPagesAnchorEl)}>Dashboard</MenuItem>
                            <MenuItem onClick={() => handleMenuClose(setPagesAnchorEl)}>Profile</MenuItem>
                        </Menu>

                        <Button
                            color="inherit"
                            endIcon={<KeyboardArrowDownIcon />}
                            onClick={(e) => handleMenuOpen(e, setAuthAnchorEl)}
                            sx={{ color: 'white' }}
                        >
                            Authentication
                        </Button>
                        <Menu
                            anchorEl={authAnchorEl}
                            open={Boolean(authAnchorEl)}
                            onClose={() => handleMenuClose(setAuthAnchorEl)}
                        >
                            <MenuItem onClick={() => handleMenuClose(setAuthAnchorEl)}>Sign In</MenuItem>
                            <MenuItem onClick={() => handleMenuClose(setAuthAnchorEl)}>Sign Up</MenuItem>
                        </Menu>

                        <Button
                            color="inherit"
                            endIcon={<KeyboardArrowDownIcon />}
                            onClick={(e) => handleMenuOpen(e, setAppAnchorEl)}
                            sx={{ color: 'white' }}
                        >
                            Application
                        </Button>
                        <Menu
                            anchorEl={appAnchorEl}
                            open={Boolean(appAnchorEl)}
                            onClose={() => handleMenuClose(setAppAnchorEl)}
                        >
                            <MenuItem onClick={() => handleMenuClose(setAppAnchorEl)}>Calendar</MenuItem>
                            <MenuItem onClick={() => handleMenuClose(setAppAnchorEl)}>Analytics</MenuItem>
                        </Menu>

                        <Button
                            color="inherit"
                            endIcon={<KeyboardArrowDownIcon />}
                            onClick={(e) => handleMenuOpen(e, setEcommerceAnchorEl)}
                            sx={{ color: 'white' }}
                        >
                            Ecommerce
                        </Button>
                        <Menu
                            anchorEl={ecommerceAnchorEl}
                            open={Boolean(ecommerceAnchorEl)}
                            onClose={() => handleMenuClose(setEcommerceAnchorEl)}
                        >
                            <MenuItem onClick={() => handleMenuClose(setEcommerceAnchorEl)}>Products</MenuItem>
                            <MenuItem onClick={() => handleMenuClose(setEcommerceAnchorEl)}>Orders</MenuItem>
                        </Menu>
                    </Box>

                    {/* Buy Now Button */}
                    <StyledButton variant="contained">
                        BUY NOW
                    </StyledButton>
                </Toolbar>
            </StyledAppBar>

            {/* Main Content */}
            <Grid container sx={{ flexGrow: 1 }}>
                {/* Left side - Futuristic Tunnel Image */}
                <Grid item xs={12} md={7}
                      sx={{
                          position: 'relative',
                          display: { xs: 'none', md: 'flex' },
                          flexDirection: 'column',
                          justifyContent: 'center',
                          alignItems: 'center',
                          backgroundImage: 'url(https://images.unsplash.com/photo-1604147706283-d7119b5b822c?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=2787&q=80)',
                          backgroundSize: 'cover',
                          backgroundPosition: 'center',
                          color: 'white',
                          padding: 4
                      }}
                >
                    <Box sx={{ textAlign: 'center', maxWidth: '80%', zIndex: 2 }}>
                        <Typography variant="subtitle1" sx={{ letterSpacing: 4, my: 2 }}>
                            INSPIRED BY THE FUTURE:
                        </Typography>
                        <Typography variant="h2" sx={{ fontWeight: 700, letterSpacing: 1 }}>
                            THE VISION UI DASHBOARD
                        </Typography>
                    </Box>
                    {/* Overlay to ensure text readability */}
                    <Box sx={{
                        position: 'absolute',
                        top: 0,
                        left: 0,
                        right: 0,
                        bottom: 0,
                        backgroundColor: 'rgba(0,0,0,0.5)',
                        zIndex: 1
                    }} />
                </Grid>

                {/* Right side - Sign In Form */}
                <Grid item xs={12} md={5}
                      sx={{
                          display: 'flex',
                          flexDirection: 'column',
                          justifyContent: 'center',
                          p: 4
                      }}
                >
                    <Box sx={{ maxWidth: 450, width: '100%', mx: 'auto' }}>
                        <Typography variant="h4" sx={{ color: 'white', mb: 1, fontWeight: 600 }}>
                            Nice to see you!
                        </Typography>
                        <Typography variant="body1" sx={{ color: 'rgba(255, 255, 255, 0.7)', mb: 4 }}>
                            Enter your email and password to sign in
                        </Typography>

                        {/* Form Fields */}
                        <Box component="form" noValidate sx={{ mt: 1 }}>
                            <Typography variant="body2" sx={{ color: 'white', mb: 1 }}>
                                Email
                            </Typography>
                            <StyledTextField
                                margin="normal"
                                required
                                fullWidth
                                id="email"
                                placeholder="Your email"
                                name="email"
                                autoComplete="email"
                                autoFocus
                                variant="outlined"
                                sx={{ mb: 3, mt: 0 }}
                            />

                            <Typography variant="body2" sx={{ color: 'white', mb: 1 }}>
                                Password
                            </Typography>
                            <StyledTextField
                                margin="normal"
                                required
                                fullWidth
                                name="password"
                                placeholder="Your password"
                                type="password"
                                id="password"
                                autoComplete="current-password"
                                variant="outlined"
                                sx={{ mt: 0 }}
                            />

                            <Box sx={{ display: 'flex', alignItems: 'center', mt: 2 }}>
                                <StyledFormControlLabel
                                    control={<BlueSwitch />}
                                    label="Remember me"
                                />
                            </Box>

                            <SignInButton
                                type="submit"
                                fullWidth
                                variant="contained"
                            >
                                SIGN IN
                            </SignInButton>

                            <Box sx={{ mt: 3, textAlign: 'center' }}>
                                <Typography variant="body2" sx={{ color: 'white' }}>
                                    Don't have an account?{' '}
                                    <Link href="#" variant="body2" sx={{ color: '#0d6efd' }}>
                                        Sign up
                                    </Link>
                                </Typography>
                            </Box>
                        </Box>
                    </Box>
                </Grid>
            </Grid>
        </Box>
    );
};

export default Login;
