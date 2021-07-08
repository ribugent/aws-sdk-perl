# Generated by default/object.tt
package Paws::Robomaker::Tool;
  use Moose;
  has Command => (is => 'ro', isa => 'Str', request_name => 'command', traits => ['NameInRequest'], required => 1);
  has ExitBehavior => (is => 'ro', isa => 'Str', request_name => 'exitBehavior', traits => ['NameInRequest']);
  has Name => (is => 'ro', isa => 'Str', request_name => 'name', traits => ['NameInRequest'], required => 1);
  has StreamOutputToCloudWatch => (is => 'ro', isa => 'Bool', request_name => 'streamOutputToCloudWatch', traits => ['NameInRequest']);
  has StreamUI => (is => 'ro', isa => 'Bool', request_name => 'streamUI', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Robomaker::Tool

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Robomaker::Tool object:

  $service_obj->Method(Att1 => { Command => $value, ..., StreamUI => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Robomaker::Tool object:

  $result = $service_obj->Method(...);
  $result->Att1->Command

=head1 DESCRIPTION

Information about a tool. Tools are used in a simulation job.

=head1 ATTRIBUTES


=head2 B<REQUIRED> Command => Str

Command-line arguments for the tool. It must include the tool
executable name.


=head2 ExitBehavior => Str

Exit behavior determines what happens when your tool quits running.
C<RESTART> will cause your tool to be restarted. C<FAIL> will cause
your job to exit. The default is C<RESTART>.


=head2 B<REQUIRED> Name => Str

The name of the tool.


=head2 StreamOutputToCloudWatch => Bool

Boolean indicating whether logs will be recorded in CloudWatch for the
tool. The default is C<False>.


=head2 StreamUI => Bool

Boolean indicating whether a streaming session will be configured for
the tool. If C<True>, AWS RoboMaker will configure a connection so you
can interact with the tool as it is running in the simulation. It must
have a graphical user interface. The default is C<False>.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Robomaker>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

