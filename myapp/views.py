from django.shortcuts import get_object_or_404, redirect, render
from django.http import JsonResponse, Http404
from .models import CustomUser,API,Tokens
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse,HttpResponseForbidden
from django.contrib.auth.hashers import check_password
from rest_framework.response import Response
from rest_framework.decorators import api_view

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>reusable functions for token authorisations
def Admin_Token_check(token):
    try:
        token_instance = Tokens.objects.get(token=token)
        if token_instance.userid:
            user_role = token_instance.userid.role
            if user_role not in ['Admin']:
                return True
        else:
            # If the token is not associated with a valid user ID, deny API creation
            return True
    except Tokens.DoesNotExist:
        # If the token is not found in the Tokens table, deny API creation
        return True

def Admin_User_Token_check(token):
    try:
            token_instance = Tokens.objects.get(token=token)
            if token_instance.userid:
                user_role = token_instance.userid.role
                if user_role not in ['Admin','User']:
                    return True
            else:
                # If the token is not associated with a valid user ID, deny API creation
                return True
    except Tokens.DoesNotExist:
        # If the token is not found in the Tokens table, deny API creation
        return True


#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> function to add the new user
def register_user(request):
    # print(request.method)
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        token = request.COOKIES.get('token')
        # checking admin tokens
        result=Admin_Token_check(token)
        if result:
           return HttpResponse("Invalid token. You are not authorized.")
        #creating user
        try:
            user = CustomUser(username=username, password=password)
            user.save()
            return redirect("/listUsers")
        except:
            return render(request, 'registration.html',{"error_message": "User already exsist"})
    return render(request, 'registration.html')

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>function to remove user
def remove_user(request,id):
    try:
        token = request.COOKIES.get('token')
        # print(token)
        #checking admin token
        result=Admin_Token_check(token)
        if result:
           return HttpResponse("Invalid token. You are not authorized.")
        user = get_object_or_404(CustomUser, id=id)
        user.delete()
        return redirect("/listUsers")
    except Http404:
        return Response({'error': 'User not found.'}, status=404)
    

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> function to list users
def list_users(request):
    users = CustomUser.objects.all()
    return render(request, 'list_users.html', {'users': users})


#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> function to update user
def updateuser(request, id):
    try:
        token = request.COOKIES.get('token')
        # >>>>checking admin tokens
        result=Admin_Token_check(token)
        print(result)
        if result:
           return HttpResponse("Invalid token. You are not authorized.")

        user = get_object_or_404(CustomUser, id=id)
        
        if request.method == 'POST':
            updated_username = request.POST.get('username')
            updated_role = request.POST.get('role')  
            user.username = updated_username
            user.role = updated_role
            user.save()
            return redirect('http://127.0.0.1:8000/listUsers')
        return render(request, 'updateUser.html', {'user': user, 'user_id': id})
        
    except CustomUser.DoesNotExist:
        return render(request, 'error.html', {'error_message': 'User not found.'})
    except Exception as e:
        return render(request, 'error.html', {'error_message': str(e)})



# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> function to create API
def createAPI(request):
    if request.method == 'POST':
        name = request.POST.get("api")
        description = request.POST.get('desc')
        token = request.COOKIES.get('token')
        # Checking admin and user tokens
        result = Admin_User_Token_check(token)
        if result:
            return HttpResponse("Invalid token. You are not authorized.")

        token_instance = Tokens.objects.get(token=token)
        user_id = token_instance.userid.id

        user = CustomUser.objects.get(id=user_id)
        if user.role not in ['User','Admin']:
            # Only Admin users can create APIs
            return HttpResponse("You are not authorized to create an API.")

        api = API(name=name, desc=description, creator=user)
        api.save()
        # Assign the API to the user creating it
        api.users.add(user)
        return redirect("http://127.0.0.1:8000/ProtectedAPI")
    return render(request, 'addAPI.html')


#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>function to map api
@csrf_exempt
@api_view(['POST','GET'])
def mapApi(request,id):
    if request.method=='POST':
        try:
            token = request.COOKIES.get('token')
            # Checking admin and user tokens
            result = Admin_User_Token_check(token)
            if result:
                return HttpResponse("Invalid token. You are not authorized.")
            try:
                apis=API.objects.get(id=id)
                # print(apis)
                try:
                    user_ids = request.data.get('username', [])
                except:
                    return HttpResponse("User not found")
                for user_id in user_ids:
                    apis.users.add(user_id)
                return redirect('/ProtectedAPI/')
            except:
                return HttpResponse("Invalid Api ID")
        except:
            return HttpResponse("Invalid Token " ,status=401)
    else:
        return render(request, "map.html")
    
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>function for list api
@api_view(['GET'])
def listAPI(request):
    token = request.COOKIES.get('token')
    try:
        token_instance = Tokens.objects.get(token=token)
        user = CustomUser.objects.filter(id=token_instance.userid_id).first()
        
        if user.role == 'User':
            print("inside if")
            apis = API.objects.filter(users=user)
        else:
            apis = API.objects.all()

        return render(request,'ProtectedAPI.html',{'apis':apis})

    except Tokens.DoesNotExist:
        return Response("Invalid token.", status=401)



#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>function to delete API
def deleteApi(request,id):
    try:
        token = request.COOKIES.get('token')
        # print(token)
        result= Admin_Token_check(token)
        if result:
            return HttpResponse("Invalid token. You are not authorized.")
        api = get_object_or_404(API, id=id)
        api.delete()
        return redirect("/ProtectedAPI")
    except Http404:
        return render(request,'error.html',{'error': 'User not found.'})
    

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>function to update api
def updateApi(request, id):
    try:
        token = request.COOKIES.get('token')
        token_instance = Tokens.objects.get(token=token)
        user = CustomUser.objects.filter(id=token_instance.userid_id).first()
        api=API.objects.filter(creator_id=user.id).first()
        try:
            if user.role=='Admin' or api.creator_id==user.id:
                if request.method == 'POST':
                    updated_name = request.POST.get('name')
                    updated_desc = request.POST.get('desc')
                    
                    api.name = updated_name
                    api.desc = updated_desc
                    api.save()
                    return redirect('http://127.0.0.1:8000/ProtectedAPI')
                
                return render(request, 'updateAPI.html', {'api': api, 'id':id})
        except:
            return render(request, 'error.html', {'error_message': '401 you are not authorized.'})
    except API.DoesNotExist:
        return render(request, 'error.html', {'error_message': 'API not found.'})
    except Exception as e:
        return render(request, 'error.html', {'error_message': str(e)})

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> function to login user
@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        try:
            user = CustomUser.objects.get(username=username)
        except:
            return render(request, 'login.html', {'error_message': 'Invalid credentials. Please try again.'})
        if check_password(password, user.password):
            # print("Inside")
            if user is not None:
                try:
                    token_instance = Tokens.objects.get(userid_id=user.id)
                    token_instance.delete()
                except Tokens.DoesNotExist:
                    pass 
                token_instance = Tokens.objects.create(userid_id=user.id)

                #>>> calling save_token function to generate token for authenticate users
                token = token_instance.save_token()
                response = HttpResponse("Token set successfully!")
                response.set_cookie('token', token)
                # return response
                u=CustomUser.objects.get(id=user.id)
                print(u.role)
                if u.role=="Admin":
                    # admin actions
                    token_instance = Tokens.objects.get(userid_id=user.id)
                    token=token_instance.token
                    # print(token)
                    response = HttpResponse(render(request, 'admin.html', {'message': 'login successful!', 'token':token}))
                    response.set_cookie('token', token)
                    return response
                elif u.role=="User":
                    #User actions
                    token_instance = Tokens.objects.get(userid_id=user.id)
                    token=token_instance.token
                    # print(token)
                    response = HttpResponse(render(request, 'admin.html', {'message': 'login successful!', 'token':token}))
                    response.set_cookie('token', token)
                    return response
                else: 
                    #viewer action
                    token_instance = Tokens.objects.get(userid_id=user.id)
                    token=token_instance.token
                    response = HttpResponse(render(request, 'admin.html', {'message': 'login successful!','token':token}))
                    response.set_cookie('token', token)
                    return response  
        else:
            return render(request, 'login.html', {'error_message': 'Password Incorrect. Please try again.'})
    return render(request, 'login.html')

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>function for deleting token of logined user (logout)
def logout(request):
    if request.method == 'GET':
        token = request.COOKIES.get('token')
        try:
            token_instance = Tokens.objects.get(token=token)
            if token_instance:
                token_instance.delete()
        except Tokens.DoesNotExist:
            raise Http404("Token not found")
        return redirect('/')  

    return render(request, 'login.html')