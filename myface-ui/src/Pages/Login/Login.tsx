﻿import React, {FormEvent, useContext, useState} from 'react';
import {Page} from "../Page/Page";
import {LoginContext} from "../../Components/LoginManager/LoginManager";
import "./Login.scss";
import { fetchlogin } from '../../Api/apiClient';

export function Login(): JSX.Element {
    const loginContext = useContext(LoginContext);
    
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    
    function tryLogin(event: FormEvent) {
        event.preventDefault();
    //     //encoded
    //    let isValid;
    //    fetch(`https://localhost:5001/users/login`, {
    //     method: "GET",
    //     headers: {
    //         "Content-Type": "application/json",
    //         "Authorization": "Basic dGVzdC11c2VyOnNlY3JldA==",
    //     }})
    //         .then(response => response.json())
    //         .then(data => isValid = data);

    //     if (isValid)
    //     {
            loginContext.logIn();
        // }
    }
    
    return (
        <Page containerClassName="login">
            <h1 className="title">Log In</h1>
            <form className="login-form" onSubmit={tryLogin}>
                <label className="form-label">
                    Username
                    <input className="form-input" type={"text"} value={username} onChange={event => setUsername(event.target.value)}/>
                </label>

                <label className="form-label">
                    Password
                    <input className="form-input" type={"password"} value={password} onChange={event => setPassword(event.target.value)}/>
                </label>
                
                <button className="submit-button" type="submit">Log In</button>
            </form>
        </Page>
    );
}