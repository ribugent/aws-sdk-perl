
package Paws::GameLift::DeregisterGameServer;
  use Moose;
  has GameServerGroupName => (is => 'ro', isa => 'Str', required => 1);
  has GameServerId => (is => 'ro', isa => 'Str', required => 1);

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'DeregisterGameServer');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::API::Response');
  class_has _result_key => (isa => 'Str', is => 'ro');
1;

### main pod documentation begin ###

=head1 NAME

Paws::GameLift::DeregisterGameServer - Arguments for method DeregisterGameServer on L<Paws::GameLift>

=head1 DESCRIPTION

This class represents the parameters used for calling the method DeregisterGameServer on the
L<Amazon GameLift|Paws::GameLift> service. Use the attributes of this class
as arguments to method DeregisterGameServer.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to DeregisterGameServer.

=head1 SYNOPSIS

    my $gamelift = Paws->service('GameLift');
    $gamelift->DeregisterGameServer(
      GameServerGroupName => 'MyGameServerGroupNameOrArn',
      GameServerId        => 'MyGameServerId',

    );

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/gamelift/DeregisterGameServer>

=head1 ATTRIBUTES


=head2 B<REQUIRED> GameServerGroupName => Str

A unique identifier for the game server group where the game server is
running. Use either the GameServerGroup name or ARN value.



=head2 B<REQUIRED> GameServerId => Str

A custom string that uniquely identifies the game server to deregister.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method DeregisterGameServer in L<Paws::GameLift>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

